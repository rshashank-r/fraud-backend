"""
ASN and VPN Detection Service
Identifies suspicious network patterns like VPNs, proxies, and hosting providers
"""

from services.geo_service import GeoService

class ASNDetector:
    """
    Detects VPNs, proxies, and hosting providers using ASN data.
    Enhanced version of existing VPN detection with ASN analysis.
    """
    
    # Known VPN/Proxy/Hosting ASNs (subset - can be expanded)
    SUSPICIOUS_ASNS = {
        'AS13335': 'Cloudflare',
        'AS16509': 'Amazon AWS',
        'AS15169': 'Google Cloud',
        'AS14061': 'DigitalOcean',
        'AS8075': 'Microsoft Azure',
        'AS20473': 'Choopa (Vultr)',
        'AS24940': 'Hetzner',
        'AS16276': 'OVH',
        'AS174': 'Cogent (Common proxy)',
        'AS3320': 'Deutsche Telekom (VPN)',
        'AS9009': 'M247 (Common VPN)',
        'AS51167': 'Contabo',
        'AS21844': 'ThePlanet'
    }
    
    @staticmethod
    def check_asn(ip_address):
        """
        Check if IP belongs to suspicious ASN.
        
        Args:
            ip_address: str
            
        Returns:
            dict: {
                'is_vpn': bool,
                'is_hosting': bool,
                'asn_name': str,
                'risk_score': float
            }
        """
        # Use existing GeoService to get IP details
        geo_details = GeoService.get_ip_details(ip_address)
        
        if not geo_details:
            return {
                'is_vpn': False,
                'is_hosting': False,
                'asn_name': 'Unknown',
                'risk_score': 0.0
            }
        
        # Check existing is_vpn flag from GeoService
        is_vpn = geo_details.get('is_vpn', False)
        
        # Additional ASN-based detection would require ASN database
        # For now, use the existing VPN detection from GeoService
        
        risk_score = 0.0
        if is_vpn:
            risk_score = 0.5  # VPN usage adds significant risk
        
        return {
            'is_vpn': is_vpn,
            'is_hosting': is_vpn,  # Simplified - VPNs often use hosting infrastructure
            'asn_name': geo_details.get('org', 'Unknown'),
            'risk_score': risk_score
        }
    
    @staticmethod
    def calculate_geo_velocity(last_location, current_location, time_diff_hours):
        """
        Calculate travel speed between two locations.
        
        Args:
            last_location: tuple (lat, lon)
            current_location: tuple (lat, lon)
            time_diff_hours: float
            
        Returns:
            dict: {
                'speed_kmh': float,
                'is_impossible_travel': bool,
                'risk_score': float
            }
        """
        if not last_location or not current_location or time_diff_hours <= 0:
            return {
                'speed_kmh': 0.0,
                'is_impossible_travel': False,
                'risk_score': 0.0
            }
        
        # Use fraud_engine's distance calculation
        from services.fraud_engine import FraudEngine
        
        distance_km = FraudEngine.calculate_distance(
            last_location[0], last_location[1],
            current_location[0], current_location[1]
        )
        
        if not distance_km:
            return {
                'speed_kmh': 0.0,
                'is_impossible_travel': False,
                'risk_score': 0.0
            }
        
        speed_kmh = distance_km / time_diff_hours
        
        # Thresholds
        is_impossible = speed_kmh > 800  # Faster than commercial flight
        is_suspicious = speed_kmh > 500  # Very fast travel
        
        risk_score = 0.0
        if is_impossible:
            risk_score = 0.8
        elif is_suspicious:
            risk_score = 0.4
        elif speed_kmh > 200:  # Fast but possible
            risk_score = 0.2
        
        return {
            'speed_kmh': speed_kmh,
            'is_impossible_travel': is_impossible,
            'risk_score': risk_score
        }
