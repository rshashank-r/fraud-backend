import geoip2.database
import os
import requests
from flask import request

class GeoService:
    _reader = None

    @classmethod
    def get_reader(cls):
        """Singleton to load the heavy database only once"""
        if cls._reader is None:
            # Use absolute path relative to this file
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, 'GeoLite2-City.mmdb')
            
            if os.path.exists(db_path):
                try:
                    cls._reader = geoip2.database.Reader(db_path)
                except Exception as e:
                    print(f"❌ Failed to load GeoLite2 DB: {e}")
            else:
                print(f"⚠️ GeoLite2-City.mmdb not found at {db_path}. Will use API fallback.")
        return cls._reader

    @staticmethod
    def get_real_ip():
        """
        Gets the real IP address, handling Proxies/Load Balancers.
        If X-Forwarded-For is present, it returns the first IP (the original client).
        """
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        return request.remote_addr

    @staticmethod
    def get_ip_details_from_api(ip_address):
        """Fallback: Get details from external API"""
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,city,lat,lon,isp,hosting,proxy"
            response = requests.get(url, timeout=3) # Short timeout for fallback
            data = response.json()

            if data.get('status') == 'fail':
                return None
            
            is_vpn = data.get('hosting', False) or data.get('proxy', False)
            
            return {
                "country": data.get('countryCode'),
                "city": data.get('city'),
                "lat": data.get('lat'),
                "lon": data.get('lon'),
                "is_vpn": is_vpn,
                "source": "API"
            }
        except Exception as e:
            print(f"❌ GeoAPI Fallback Error: {e}")
            return None

    @staticmethod
    def get_ip_details(ip_address):
        """
        Returns Country and Coordinates. Tries Local DB first, then API.
        """
        # 1. Handle Localhost
        if ip_address in ['127.0.0.1', '::1']:
            return {"country": "LO", "city": "Localhost", "lat": 0.0, "lon": 0.0, "is_vpn": False}

        # 2. Try Local DB
        reader = GeoService.get_reader()
        if reader:
            try:
                response = reader.city(ip_address)
                is_vpn = False
                if response.traits.is_hosting_provider or response.traits.is_proxy:
                    is_vpn = True
                    
                return {
                    "country": response.country.iso_code,
                    "city": response.city.name,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                    "is_vpn": is_vpn,
                    "source": "DB"
                }
            except Exception:
                # IP not found in DB or DB error -> Fallthrough to API
                pass

        # 3. Fallback to API
        return GeoService.get_ip_details_from_api(ip_address)

    @staticmethod
    def get_location_name(ip_address):
        """Returns 'City, Country' string or 'Unknown'"""
        try:
            details = GeoService.get_ip_details(ip_address)
            if details:
                city = details.get('city')
                country = details.get('country')
                if city and country:
                    return f"{city}, {country}"
                if country:
                    return country
        except:
            pass
        return "Unknown"