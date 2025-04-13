# ☁️ Cloud Detective

<p align="center">
  <img src="https://github.com/user-attachments/assets/0a9af41e-7c4a-4d42-ba63-a89530778b74" alt="Banner">
</p>


## 🌪️ Introduction

This tool is designed to help security professionals, auditors, and researchers identify the cloud hosting provider behind a set of domains/subdomains. By analyzing DNS records (A, CNAME) and the technologies in use, it checks whether the domains are hosted on platforms such as **Azure**, **Google Cloud**, or **AWS**.

The tool checks the IP addresses associated with the domain names against known IP ranges for these cloud providers. Additionally, it uses `WhatWeb` to detect web technology stack footprints that could reveal the hosting platform. 

Whether you are conducting a red team engagement, a penetration test, or just curious about where certain domains are hosted, this tool will give you a quick answer.

## 📖 Installation

* Clone the repository:

    ```bash
    git clone https://github.com/Slayer0x/Cloud-Detective.git
    cd Cloud-Detective
    ```

* Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

*  Ensure `WhatWeb` is installed on your system:

    ```bash
    sudo apt-get install whatweb
    ```
* Download the latest Azure IP ranges:
    ```
    https://www.microsoft.com/en-us/download/details.aspx?id=56519
    ```
    Once downloaded, move the `.json` file to the `Cloud-Detective` directory and rename it to `ServiceTags_Public.json`, we need to do this because Azure doesn't have a public API to download the CIDR ranges in use like the other clouds.

## 🛠️ Usage

* Command Line Arguments:

```bash
# Standard scanner execution
python cloud_detective.py <subdomains.txt>
# Using a custom DNS
python cloud_detective.py <subdomains.txt> -d 1.1.1.1
# Custom workers
python cloud_detective.py <subdomains.txt> -w 15

# Summary
cloud_detective.py [-h] [-d DNS] [-w WORKERS] [-o OUTPUT] files [files ...]

```

## ⚠️ Known Issues

By using `Whatweb`, we sometimes get false positives. For example, websites that use Google Fonts or similar technologies might be incorrectly identified as being hosted on Google Cloud.

I might update this in the future, but these false positives are usually easy to spot. If a subdomain is only detected by `Whatweb`, just take a quick look at the site's actual technologies to verify.

## 🙋‍♂️ Pull Requests
Feel free to submit pull requests with new checks or improvements.

## 📽️ Video

<p align="center">
  <img src= https://github.com/user-attachments/assets/7633ed26-8ddb-447e-a04c-c29abb6851d0 alt="Demo" width="700"/>
</p>

