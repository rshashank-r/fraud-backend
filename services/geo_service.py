import geoip2.database
import os
from flask import request # Import Request

class GeoService:
    _reader = None

    @classmethod
    def get_reader(cls):
        """Singleton to load the heavy database only once"""
        if cls._reader is None:
            db_path = os.path.join(os.getcwd(), 'GeoLite2-City.mmdb')
            if os.path.exists(db_path):
                cls._reader = geoip2.database.Reader(db_path)
            else:
                print("⚠️ GeoLite2-City.mmdb not found. Geo-location disabled.")
        return cls._reader

    @staticmethod
    def get_real_ip():
        """
        Gets the real IP address, handling Proxies/Load Balancers.
        If X-Forwarded-For is present, it returns the first IP (the original client).
        """
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0]
        return request.remote_addr

    @staticmethod
    def get_ip_details(ip_address):
        """
        Returns Country and Coordinates for a given IP.
        """
        # 1. Handle Localhost (No Geo Data)
        if ip_address in ['127.0.0.1', '::1']:
            return {"country": "LO", "lat": 0.0, "lon": 0.0, "is_vpn": False}

        reader = GeoService.get_reader()
        if not reader: 
            return None 

        try:
            response = reader.city(ip_address)
            
            # 2. Simple VPN Detection Heuristic
            # (Real VPN detection requires paid APIs like IPQualityScore, but this works for basic hosting)
            is_vpn = False
            if response.traits.is_hosting_provider or response.traits.is_proxy:
                is_vpn = True
                
            return {
                "country": response.country.iso_code,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "is_vpn": is_vpn
            }
        except Exception as e:
            # IP not found in DB
            return None
        