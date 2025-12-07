#!/usr/bin/env python3
"""
Test script untuk memverifikasi country_database.json
"""
import json
import sys

def test_country_database():
    """Test all aspects of country database"""
    print("🔍 Testing country_database.json\n")
    print("=" * 60)
    
    try:
        with open('country_database.json', 'r', encoding='utf-8') as f:
            db = json.load(f)
    except Exception as e:
        print(f"❌ ERROR: Cannot load file: {e}")
        return False
    
    # Test basic structure
    print(f"\n✅ File loaded successfully")
    print(f"   Version: {db.get('version', 'N/A')}")
    print(f"   Last Updated: {db.get('last_updated', 'N/A')}")
    
    countries = db.get('countries', {})
    print(f"\n📊 Total Countries: {len(countries)}")
    print(f"   Countries: {', '.join(countries.keys())}")
    
    # Test each country
    total_ips = 0
    total_cities = 0
    total_devices = 0
    
    print("\n" + "=" * 60)
    print("DETAILED COUNTRY ANALYSIS")
    print("=" * 60)
    
    for country_code, country_data in countries.items():
        print(f"\n🌍 {country_code} - {country_data.get('name', 'Unknown')}")
        print(f"   Language: {country_data.get('language', 'N/A')}")
        print(f"   Timezone: {country_data.get('timezone', 'N/A')}")
        print(f"   Currency: {country_data.get('currency', 'N/A')}")
        
        # ISP Analysis
        isps = country_data.get('isps', {})
        mobile_isps = isps.get('mobile', {})
        broadband_isps = isps.get('broadband', {})
        
        print(f"   📱 Mobile ISPs: {len(mobile_isps)}")
        for isp_name, isp_data in mobile_isps.items():
            ranges = isp_data.get('ranges', [])
            print(f"      • {isp_name}: {len(ranges)} IP ranges ({isp_data.get('asn', 'N/A')})")
            total_ips += len(ranges)
        
        print(f"   🌐 Broadband ISPs: {len(broadband_isps)}")
        for isp_name, isp_data in broadband_isps.items():
            ranges = isp_data.get('ranges', [])
            print(f"      • {isp_name}: {len(ranges)} IP ranges ({isp_data.get('asn', 'N/A')})")
            total_ips += len(ranges)
        
        # Cities
        cities = country_data.get('cities', [])
        total_cities += len(cities)
        print(f"   🏙️  Cities: {len(cities)}")
        if cities:
            print(f"      Sample: {', '.join([c['name'] for c in cities[:3]])}")
        
        # Devices
        devices = country_data.get('devices', {})
        mobile_devices = devices.get('mobile', [])
        desktop_devices = devices.get('desktop', [])
        total_devices += len(mobile_devices) + len(desktop_devices)
        
        print(f"   📱 Mobile Devices: {len(mobile_devices)}")
        if mobile_devices:
            print(f"      Sample: {', '.join(mobile_devices[:3])}")
        
        print(f"   💻 Desktop Devices: {len(desktop_devices)}")
        if desktop_devices:
            print(f"      Sample: {', '.join(desktop_devices[:2])}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY STATISTICS")
    print("=" * 60)
    print(f"✅ Total Countries: {len(countries)}")
    print(f"✅ Total IP Ranges: {total_ips}")
    print(f"✅ Total Cities: {total_cities}")
    print(f"✅ Total Devices: {total_devices}")
    print(f"✅ Average IP Ranges per Country: {total_ips/len(countries):.1f}")
    print(f"✅ Average Cities per Country: {total_cities/len(countries):.1f}")
    print(f"✅ Average Devices per Country: {total_devices/len(countries):.1f}")
    
    print("\n" + "=" * 60)
    print("🎉 ALL TESTS PASSED!")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = test_country_database()
    sys.exit(0 if success else 1)
