from src_anamorphic_ElGamal.utils import sha256_hash, generate_random_bytes

class NIZK_Mock:
    def __init__(self):
        pass

    def setup(self, lambda_bits):
        sigma = generate_random_bytes(lambda_bits // 8)
        return sigma

    def Prover(self, instance, witness, sigma):
        instance_str = str(instance)
        witness_str = str(witness)
        proof = sha256_hash(instance_str + witness_str + str(sigma) + "PROVED") 
        return proof

    def Verifier(self, instance, proof, sigma):
        if isinstance(proof, bytes) and len(proof) == 32:
            return True
        return False

    def Simulator_S0(self, lambda_bits):
        simulated_sigma = generate_random_bytes(lambda_bits // 8)
        auxiliary_info = sha256_hash("SIMULATION_SECRET_TOKEN" + str(lambda_bits))
        return simulated_sigma, auxiliary_info

    def Simulator_S1(self, instance, aux_info):
        instance_str = str(instance)
        simulated_proof = sha256_hash(instance_str + str(aux_info) + "SIMULATED_PROVED")
        return simulated_proof
