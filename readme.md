# SOAR in Python

## Set up

1. Install Python

`sudo apt update && sudo apt upgrade`
`sudo apt install python3`

2. Install Python dependencies/requirements

`pip install pyyaml jinja2`

## Run

`python main.py <alert_file.json>`

## Results

Executing script..

<img width="699" height="73" alt="image" src="https://github.com/user-attachments/assets/fe15a843-8d5c-4b61-a9de-220e207a998d" />

**Markdown preview**

<img width="1154" height="809" alt="image" src="https://github.com/user-attachments/assets/e23327b1-2191-4a38-8c74-5bcfae981974" />

## Tree

```
├── alerts
│   ├── sentinel.json
│   └── sumologic.json
├── configs
│   ├── allowlists.yml
│   ├── connectors.yml
│   └── mitre_map.yml
├── main.py
├── mocks
│   └── it
│       ├── anomali_ip_1.2.3.4.json
│       ├── defender_ti_domain_bad.example.net.json
│       └── reversinglabs_sha256_7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0.json
├── out
│   ├── incidents
│   │   ├── sen-001.json
│   │   └── sumo-abc.json
│   ├── isolation.log
│   └── summaries
│       ├── sen-001.md
│       └── sumo-abc.md
└── readme.md
```
