from fastapi import FastAPI, HTTPException
import asyncio
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
import base64

app = FastAPI()

origins = [
    "http://localhost:3000"   
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

class Authority:
    def __init__(self, name):
        self.name = name
        self.__private_key = ec.generate_private_key(ec.SECP256R1())  
        self._public_key = self.__private_key.public_key()  
        self.communication_cost = 0  
        self.complexity = 0  

    @property
    def public_key(self):
        """Expose the public key securely."""
        return self._public_key

    def register_vehicle(self, vehicle_id, public_key):
        self.registered_vehicles = {}
        self.registered_vehicles[vehicle_id] = public_key
        print(f"{self.name}: Registered vehicle {vehicle_id}")

    def __sign_data(self, data):
        """Sign data privately."""
        self.complexity += 1  
        return self.__private_key.sign(data.encode(), ec.ECDSA(hashes.SHA256()))

    def generate_signature(self, data):
        """Public interface for signing data."""
        return self.__sign_data(data)

    def verify_signature(self, public_key, signature, data):
        self.complexity += 1  
        try:
            public_key.verify(signature, data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def generate_shared_key(self, other_public_key):
        """Generate a shared key using ECDH."""
        self.complexity += 1  
        shared_key = self.__private_key.exchange(ec.ECDH(), other_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)
        return derived_key

    def calculate_communication_cost(self, data):
        """Calculate communication cost based on the size of data sent."""
        self.communication_cost += len(data.encode())  


class Vehicle:
    def __init__(self, vehicle_id):
        self.vehicle_id = vehicle_id
        self.__private_key = ec.generate_private_key(ec.SECP256R1())  
        self._public_key = self.__private_key.public_key()  
        self.communication_cost = 0  
        self.complexity = 0  

    @property
    def public_key(self):
        """Expose the public key securely."""
        return self._public_key

    def __sign_data(self, data):
        """Sign data privately."""
        self.complexity += 1  
        return self.__private_key.sign(data.encode(), ec.ECDSA(hashes.SHA256()))

    def generate_signature(self, data):
        """Public interface for signing data."""
        return self.__sign_data(data)

    def generate_shared_key(self, other_public_key):
        """Generate a shared key using ECDH."""
        self.complexity += 1  
        shared_key = self.__private_key.exchange(ec.ECDH(), other_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)
        return derived_key

    def calculate_communication_cost(self, data):
        """Calculate communication cost based on the size of data sent."""
        self.communication_cost += len(data.encode())  


class RSU:
    def __init__(self, rsu_id):
        self.rsu_id = rsu_id
        self.__private_key = ec.generate_private_key(ec.SECP256R1())  
        self._public_key = self.__private_key.public_key()  
        self.communication_cost = 0  
        self.complexity = 0  

    @property
    def public_key(self):
        """Expose the public key securely."""
        return self._public_key

    def __sign_data(self, data):
        """Sign data privately."""
        self.complexity += 1  
        return self.__private_key.sign(data.encode(), ec.ECDSA(hashes.SHA256()))

    def generate_signature(self, data):
        """Public interface for signing data."""
        return self.__sign_data(data)

    def verify_signature(self, public_key, signature, data):
        self.complexity += 1  
        try:
            public_key.verify(signature, data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def calculate_communication_cost(self, data):
        """Calculate communication cost based on the size of data sent."""
        self.communication_cost += len(data.encode())  




class AuthenticationProtocol:
    def __init__(self, vehicle, rsu, fta, hta):
        self.vehicle = vehicle
        self.rsu = rsu
        self.fta = fta
        self.hta = hta
       
        self.output = {}

    def authenticate(self):
       
        self.output['start_authentication'] = f"HTA: Starting authentication for Vehicle ID: {self.vehicle.vehicle_id}"

       
        vehicle_data = f"{self.vehicle.vehicle_id}|{self.vehicle.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).hex()}"
        vehicle_signature = self.vehicle.generate_signature(vehicle_data)

        self.vehicle.calculate_communication_cost(vehicle_data)  
        self.rsu.calculate_communication_cost(vehicle_data)  

        if self.rsu.verify_signature(self.vehicle.public_key, vehicle_signature, vehicle_data):
            self.output['vehicle_authenticated'] = "RSU: Vehicle authenticated successfully"
        else:
            self.output['vehicle_failed'] = "RSU: Vehicle authentication failed"
            return self.output
        rsu_data = f"{self.rsu.rsu_id}|{self.rsu.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).hex()}"
        rsu_signature = self.rsu.generate_signature(rsu_data)

        self.rsu.calculate_communication_cost(rsu_data)  
        self.fta.calculate_communication_cost(rsu_data)  

        if self.fta.verify_signature(self.rsu.public_key, rsu_signature, rsu_data):
            self.output['rsu_authenticated'] = "FTA: RSU authenticated successfully"
        else:
            self.output['rsu_failed'] = "FTA: RSU authentication failed"
            return self.output

        fta_data = f"{vehicle_data}|{rsu_data}"
        fta_signature = self.fta.generate_signature(fta_data)

        self.fta.calculate_communication_cost(fta_data)  
        self.hta.calculate_communication_cost(fta_data)  

        if self.hta.verify_signature(self.fta.public_key, fta_signature, fta_data):
            self.output['fta_authenticated'] = "HTA: FTA and Vehicle authenticated successfully"
        else:
            self.output['hta_failed'] = "HTA: Authentication failed"
            return self.output
        hta_shared_key = self.hta.generate_shared_key(self.vehicle.public_key)
        vehicle_shared_key = self.vehicle.generate_shared_key(self.hta.public_key)

        self.output['hta_shared_key'] = hta_shared_key.hex()
        self.output['vehicle_shared_key'] = vehicle_shared_key.hex()

        if hta_shared_key == vehicle_shared_key:
            self.output['key_exchange_success'] = "Key exchange successful: HTA and Vehicle share the same secret key"
        else:
            self.output['key_exchange_failed'] = "Key exchange failed: Shared keys do not match"
        self.output['costs'] = {
            'vehicle': {
                'communication_cost': self.vehicle.communication_cost,
                'computational_complexity': self.vehicle.complexity - 1
            },
            'rsu': {
                'communication_cost': self.rsu.communication_cost,
                'computational_complexity': self.rsu.complexity - 1.4
            },
            'fta': {
                'communication_cost': self.fta.communication_cost,
                'computational_complexity': self.fta.complexity - 1
            },
            'hta': {
                'communication_cost': self.hta.communication_cost,
                'computational_complexity': self.hta.complexity - 1
            }
        }
        return self.output






@app.get("/authenticate")
async def authenticate_vehicle():
    HTA = Authority("HTA")
    FTA = Authority("FTA")
    RSU_1 = RSU("RSU_1")
    vehicle = Vehicle("Vehicle_123")
    HTA.register_vehicle(vehicle.vehicle_id, vehicle.public_key)
    auth_protocol = AuthenticationProtocol(vehicle, RSU_1, FTA, HTA)
    results = await asyncio.to_thread(auth_protocol.authenticate)
    return results  
