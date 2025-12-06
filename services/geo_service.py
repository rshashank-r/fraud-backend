import geoip2.database
import os
from flask import request # Import Request

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
                print(f"⚠️ GeoLite2-City.mmdb not found at {db_path}. Geo-location disabled.")
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
    def get_ip_details(ip_address):
        """
        Returns Country and Coordinates for a given IP.
        """
        # 1. Handle Localhost (No Geo Data)
        if ip_address in ['127.0.0.1', '::1']:
            return {"country": "LO", "city": "Localhost", "lat": 0.0, "lon": 0.0, "is_vpn": False}

        reader = GeoService.get_reader()
        if not reader: 
            return None 

        try:
            response = reader.city(ip_address)
            
            # 2. Simple VPN Detection Heuristic
            is_vpn = False
            if response.traits.is_hosting_provider or response.traits.is_proxy:
                is_vpn = True
                
            return {
                "country": response.country.iso_code,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "is_vpn": is_vpn
            }
        except Exception as e:
            # IP not found in DB
            return None

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