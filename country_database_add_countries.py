import json

# Load existing comprehensive database
with open('country_database.json', 'r') as f:
    data = json.load(f)

# Add more countries with comprehensive data
additional_countries = {
    "US": {
        "name": "United States",
        "language": "en-US",
        "timezone": "America/New_York",
        "locale": "en_US",
        "currency": "USD",
        "isps": {
            "mobile": {
                "verizon": {
                    "asn": "AS22394",
                    "name": "Verizon Wireless",
                    "ranges": [
                        "174.192.0.0/10", "166.137.0.0/16", "98.192.0.0/11",
                        "71.192.0.0/12", "75.128.0.0/10", "173.192.0.0/10",
                        "68.96.0.0/11", "174.96.0.0/11"
                    ]
                },
                "att": {
                    "asn": "AS20057",
                    "name": "AT&T Mobility",
                    "ranges": [
                        "166.147.0.0/16", "107.77.0.0/16", "99.0.0.0/10",
                        "135.0.0.0/9", "12.0.0.0/9", "108.0.0.0/8"
                    ]
                },
                "tmobile": {
                    "asn": "AS21928",
                    "name": "T-Mobile USA",
                    "ranges": [
                        "172.32.0.0/11", "172.56.0.0/13", "208.54.0.0/16",
                        "54.240.0.0/12", "155.96.0.0/12", "174.0.0.0/9"
                    ]
                }
            },
            "broadband": {
                "comcast": {
                    "asn": "AS7922",
                    "name": "Comcast Cable",
                    "ranges": [
                        "73.0.0.0/8", "98.192.0.0/10", "24.0.0.0/8",
                        "68.32.0.0/11", "96.0.0.0/9", "50.128.0.0/9"
                    ]
                },
                "spectrum": {
                    "asn": "AS11351",
                    "name": "Charter/Spectrum",
                    "ranges": [
                        "66.75.0.0/16", "71.56.0.0/13", "24.56.0.0/13",
                        "76.0.0.0/9", "97.64.0.0/11", "72.0.0.0/12"
                    ]
                }
            }
        },
        "cities": [
            {"name": "New York", "lat": 40.7128, "lon": -74.006},
            {"name": "Los Angeles", "lat": 34.0522, "lon": -118.2437},
            {"name": "Chicago", "lat": 41.8781, "lon": -87.6298},
            {"name": "Houston", "lat": 29.7604, "lon": -95.3698},
            {"name": "Phoenix", "lat": 33.4484, "lon": -112.074},
            {"name": "Philadelphia", "lat": 39.9526, "lon": -75.1652},
            {"name": "San Antonio", "lat": 29.4241, "lon": -98.4936},
            {"name": "San Diego", "lat": 32.7157, "lon": -117.1611},
            {"name": "Dallas", "lat": 32.7767, "lon": -96.797},
            {"name": "San Jose", "lat": 37.3382, "lon": -121.8863}
        ],
        "devices": {
            "mobile": [
                "iPhone 15 Pro Max", "iPhone 15 Pro", "iPhone 15", "iPhone 14 Pro Max",
                "Samsung Galaxy S24 Ultra", "Samsung Galaxy S24+", "Samsung Galaxy S24",
                "Samsung Galaxy S23 Ultra", "Google Pixel 8 Pro", "Google Pixel 8",
                "Google Pixel 7 Pro", "OnePlus 12", "Motorola Edge 40 Pro"
            ],
            "desktop": [
                "MacBook Pro 16-inch", "MacBook Pro 14-inch", "MacBook Air M3",
                "Dell XPS 15", "Dell XPS 13", "HP Spectre x360",
                "Lenovo ThinkPad X1 Carbon", "Microsoft Surface Laptop 5"
            ]
        }
    },
    "MY": {
        "name": "Malaysia",
        "language": "ms-MY",
        "timezone": "Asia/Kuala_Lumpur",
        "locale": "ms_MY",
        "currency": "MYR",
        "isps": {
            "mobile": {
                "maxis": {
                    "asn": "AS9930",
                    "name": "Maxis Communications",
                    "ranges": [
                        "175.136.0.0/13", "60.48.0.0/12", "202.75.0.0/16",
                        "124.13.0.0/16", "113.210.0.0/15", "175.143.0.0/16"
                    ]
                },
                "celcom": {
                    "asn": "AS10030",
                    "name": "Celcom Axiata",
                    "ranges": [
                        "175.136.0.0/13", "113.210.0.0/15", "202.188.0.0/14",
                        "60.53.0.0/16", "124.6.0.0/15"
                    ]
                },
                "digi": {
                    "asn": "AS4818",
                    "name": "DiGi Telecommunications",
                    "ranges": [
                        "1.32.0.0/12", "14.192.0.0/12", "27.64.0.0/14",
                        "101.50.0.0/15", "110.4.0.0/14"
                    ]
                }
            },
            "broadband": {
                "tm": {
                    "asn": "AS4788",
                    "name": "Telekom Malaysia",
                    "ranges": [
                        "175.136.0.0/13", "60.48.0.0/12", "124.12.0.0/14",
                        "101.50.0.0/15", "27.64.0.0/14"
                    ]
                },
                "time": {
                    "asn": "AS45960",
                    "name": "TIME dotCom",
                    "ranges": [
                        "110.4.0.0/14", "119.40.0.0/14", "202.70.0.0/15",
                        "175.143.0.0/16"
                    ]
                }
            }
        },
        "cities": [
            {"name": "Kuala Lumpur", "lat": 3.139, "lon": 101.6869},
            {"name": "George Town", "lat": 5.4164, "lon": 100.3327},
            {"name": "Johor Bahru", "lat": 1.4655, "lon": 103.7578},
            {"name": "Shah Alam", "lat": 3.0733, "lon": 101.5185},
            {"name": "Petaling Jaya", "lat": 3.1073, "lon": 101.6067}
        ],
        "devices": {
            "mobile": [
                "iPhone 15 Pro", "Samsung Galaxy S24", "Samsung Galaxy A54",
                "OPPO Reno 10", "Xiaomi Redmi Note 12 Pro", "Vivo V29",
                "realme 11 Pro", "OnePlus Nord 3", "Huawei P60"
            ],
            "desktop": [
                "MacBook Air", "ASUS VivoBook", "HP Pavilion 14",
                "Dell Inspiron 15", "Lenovo IdeaPad"
            ]
        }
    },
    "SG": {
        "name": "Singapore",
        "language": "en-SG",
        "timezone": "Asia/Singapore",
        "locale": "en_SG",
        "currency": "SGD",
        "isps": {
            "mobile": {
                "singtel": {
                    "asn": "AS7473",
                    "name": "Singtel Mobile",
                    "ranges": [
                        "42.60.0.0/14", "116.14.0.0/15", "116.89.0.0/16",
                        "27.125.0.0/16", "182.55.0.0/16", "49.128.0.0/13"
                    ]
                },
                "starhub": {
                    "asn": "AS4657",
                    "name": "StarHub Mobile",
                    "ranges": [
                        "27.104.0.0/13", "203.116.0.0/14", "27.125.128.0/17",
                        "182.19.0.0/16"
                    ]
                },
                "m1": {
                    "asn": "AS9829",
                    "name": "M1 Limited",
                    "ranges": [
                        "43.251.0.0/16", "202.168.0.0/15", "111.223.0.0/16"
                    ]
                }
            },
            "broadband": {
                "singtel_fiber": {
                    "asn": "AS7473",
                    "name": "Singtel Broadband",
                    "ranges": [
                        "42.60.0.0/14", "116.88.0.0/13", "182.55.0.0/16",
                        "202.156.0.0/14"
                    ]
                },
                "starhub_fiber": {
                    "asn": "AS4657",
                    "name": "StarHub Broadband",
                    "ranges": [
                        "27.104.0.0/13", "203.117.0.0/16", "58.182.0.0/15"
                    ]
                }
            }
        },
        "cities": [
            {"name": "Singapore", "lat": 1.3521, "lon": 103.8198},
            {"name": "Jurong West", "lat": 1.3404, "lon": 103.7090},
            {"name": "Woodlands", "lat": 1.4382, "lon": 103.7891}
        ],
        "devices": {
            "mobile": [
                "iPhone 15 Pro Max", "Samsung Galaxy S24 Ultra", "OnePlus 12",
                "Google Pixel 8 Pro", "OPPO Find X7", "Xiaomi 14 Ultra"
            ],
            "desktop": [
                "MacBook Pro", "ASUS ZenBook", "Dell XPS 15",
                "HP Spectre x360", "Microsoft Surface Laptop"
            ]
        }
    },
    "TH": {
        "name": "Thailand",
        "language": "th-TH",
        "timezone": "Asia/Bangkok",
        "locale": "th_TH",
        "currency": "THB",
        "isps": {
            "mobile": {
                "ais": {
                    "asn": "AS131090",
                    "name": "AIS (Advanced Info Service)",
                    "ranges": [
                        "49.228.0.0/14", "180.180.0.0/14", "171.5.0.0/16",
                        "1.0.0.0/11", "110.78.0.0/15", "122.154.0.0/15"
                    ]
                },
                "true": {
                    "asn": "AS17552",
                    "name": "True Move H",
                    "ranges": [
                        "110.164.0.0/14", "171.96.0.0/13", "49.48.0.0/12",
                        "183.88.0.0/14", "180.183.0.0/16"
                    ]
                },
                "dtac": {
                    "asn": "AS23969",
                    "name": "DTAC TriNet",
                    "ranges": [
                        "101.0.0.0/13", "110.170.0.0/15", "171.6.0.0/15",
                        "180.183.0.0/16"
                    ]
                }
            },
            "broadband": {
                "3bb": {
                    "asn": "AS45629",
                    "name": "3BB Broadband",
                    "ranges": [
                        "49.228.0.0/14", "122.154.0.0/15", "103.13.0.0/16",
                        "27.55.0.0/16"
                    ]
                },
                "true_fiber": {
                    "asn": "AS17552",
                    "name": "True Online",
                    "ranges": [
                        "110.164.0.0/14", "171.96.0.0/13", "183.88.0.0/14",
                        "49.48.0.0/12"
                    ]
                }
            }
        },
        "cities": [
            {"name": "Bangkok", "lat": 13.7563, "lon": 100.5018},
            {"name": "Chiang Mai", "lat": 18.7883, "lon": 98.9853},
            {"name": "Phuket", "lat": 7.8804, "lon": 98.3923},
            {"name": "Pattaya", "lat": 12.9236, "lon": 100.8825},
            {"name": "Hat Yai", "lat": 7.0078, "lon": 100.4753}
        ],
        "devices": {
            "mobile": [
                "iPhone 15 Pro", "Samsung Galaxy S24", "OPPO Reno 10",
                "Vivo V29", "Xiaomi Redmi Note 12", "realme 11 Pro",
                "Samsung Galaxy A54", "OnePlus Nord 3"
            ],
            "desktop": [
                "MacBook Air", "ASUS VivoBook", "HP Pavilion",
                "Lenovo IdeaPad", "Acer Aspire"
            ]
        }
    },
    "VN": {
        "name": "Vietnam",
        "language": "vi-VN",
        "timezone": "Asia/Ho_Chi_Minh",
        "locale": "vi_VN",
        "currency": "VND",
        "isps": {
            "mobile": {
                "viettel": {
                    "asn": "AS7552",
                    "name": "Viettel Mobile",
                    "ranges": [
                        "113.160.0.0/11", "171.224.0.0/11", "27.0.0.0/9",
                        "14.224.0.0/11", "42.112.0.0/13", "171.240.0.0/13"
                    ]
                },
                "vinaphone": {
                    "asn": "AS45899",
                    "name": "VNPT VinaPhone",
                    "ranges": [
                        "113.160.0.0/11", "123.16.0.0/12", "171.244.0.0/14",
                        "14.160.0.0/11", "116.96.0.0/12"
                    ]
                },
                "mobifone": {
                    "asn": "AS18403",
                    "name": "MobiFone",
                    "ranges": [
                        "27.72.0.0/13", "117.0.0.0/13", "118.68.0.0/14",
                        "171.248.0.0/13"
                    ]
                }
            },
            "broadband": {
                "fpt": {
                    "asn": "AS18403",
                    "name": "FPT Telecom",
                    "ranges": [
                        "113.160.0.0/11", "14.224.0.0/11", "171.224.0.0/11",
                        "27.0.0.0/9", "42.112.0.0/13"
                    ]
                },
                "vnpt": {
                    "asn": "AS45899",
                    "name": "VNPT Internet",
                    "ranges": [
                        "113.160.0.0/11", "123.16.0.0/12", "171.244.0.0/14",
                        "14.160.0.0/11"
                    ]
                }
            }
        },
        "cities": [
            {"name": "Ho Chi Minh City", "lat": 10.8231, "lon": 106.6297},
            {"name": "Hanoi", "lat": 21.0278, "lon": 105.8342},
            {"name": "Da Nang", "lat": 16.0544, "lon": 108.2022},
            {"name": "Can Tho", "lat": 10.0341, "lon": 105.7222},
            {"name": "Hai Phong", "lat": 20.8449, "lon": 106.6881}
        ],
        "devices": {
            "mobile": [
                "Samsung Galaxy A54", "OPPO Reno 10", "Xiaomi Redmi Note 12",
                "Vivo V29", "realme 11 Pro", "Samsung Galaxy A34",
                "OPPO A78", "Xiaomi Poco X6"
            ],
            "desktop": [
                "ASUS VivoBook", "Dell Vostro", "HP 15s",
                "Lenovo IdeaPad", "Acer Aspire"
            ]
        }
    },
    "PH": {
        "name": "Philippines",
        "language": "en-PH",
        "timezone": "Asia/Manila",
        "locale": "en_PH",
        "currency": "PHP",
        "isps": {
            "mobile": {
                "globe": {
                    "asn": "AS4775",
                    "name": "Globe Telecom",
                    "ranges": [
                        "112.198.0.0/15", "120.28.0.0/14", "180.190.0.0/15",
                        "49.144.0.0/12", "180.192.0.0/12", "202.90.0.0/15"
                    ]
                },
                "smart": {
                    "asn": "AS10139",
                    "name": "Smart Communications",
                    "ranges": [
                        "112.198.0.0/15", "110.54.0.0/15", "49.145.0.0/16",
                        "180.194.0.0/15", "112.204.0.0/14"
                    ]
                },
                "dito": {
                    "asn": "AS139084",
                    "name": "DITO Telecommunity",
                    "ranges": [
                        "103.130.112.0/20", "180.193.0.0/16", "103.130.0.0/18"
                    ]
                }
            },
            "broadband": {
                "pldt": {
                    "asn": "AS9299",
                    "name": "PLDT Fibr",
                    "ranges": [
                        "112.198.0.0/15", "124.105.0.0/16", "180.190.0.0/12",
                        "202.90.0.0/15", "49.144.0.0/12"
                    ]
                },
                "converge": {
                    "asn": "AS17639",
                    "name": "Converge ICT",
                    "ranges": [
                        "103.28.104.0/21", "103.76.0.0/14", "110.54.128.0/17",
                        "202.57.128.0/17"
                    ]
                }
            }
        },
        "cities": [
            {"name": "Manila", "lat": 14.5995, "lon": 120.9842},
            {"name": "Quezon City", "lat": 14.6760, "lon": 121.0437},
            {"name": "Davao City", "lat": 7.1907, "lon": 125.4553},
            {"name": "Cebu City", "lat": 10.3157, "lon": 123.8854},
            {"name": "Makati", "lat": 14.5547, "lon": 121.0244}
        ],
        "devices": {
            "mobile": [
                "Samsung Galaxy A54", "Xiaomi Redmi Note 12", "Vivo V29",
                "OPPO A78", "realme 11 Pro", "Samsung Galaxy A34",
                "Vivo Y36", "OPPO Reno 8", "Xiaomi Poco X6"
            ],
            "desktop": [
                "ASUS VivoBook", "Lenovo IdeaPad", "HP 14s",
                "Acer Aspire", "Dell Inspiron"
            ]
        }
    }
}

# Merge with existing data
data["countries"].update(additional_countries)

# Save updated database
with open('country_database.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"✓ Successfully added {len(additional_countries)} countries")
print(f"✓ Total countries: {len(data['countries'])}")

# Calculate total IP ranges
total_ranges = 0
for country_data in data["countries"].values():
    for isp_type in ["mobile", "broadband"]:
        for isp in country_data["isps"].get(isp_type, {}).values():
            total_ranges += len(isp["ranges"])

print(f"✓ Total IP ranges across all countries: {total_ranges}")
