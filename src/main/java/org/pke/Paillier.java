package org.pke;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Paillier {

    public class PublicKey{
        private BigInteger n, g;

        public PublicKey(BigInteger n, BigInteger g){
            this.n = n;
            this.g = g;
        }

        public BigInteger getN(){
            return n;
        }

        public BigInteger getG(){
            return g;
        }
    }

    public class PrivateKey{
        private BigInteger lambda, mu;

        public PrivateKey(BigInteger lambda, BigInteger mu){
            this.lambda = lambda;
            this.mu = mu;
        }

        public BigInteger getLambda(){
            return lambda;
        }

        public BigInteger getMu(){
            return mu;
        }
    }

    private final int CERTAINTY = 64;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    public PublicKey getPublicKey(){
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void keyGeneration(int k){

        BigInteger p_prime, q_prime, p, q;

        do{
            p_prime = new BigInteger(k, CERTAINTY, new SecureRandom());
            p = (p_prime.multiply(BigInteger.valueOf(2))).add(BigInteger.ONE);

        }while (!p.isProbablePrime(CERTAINTY));

        do{
            do{
                q_prime = new BigInteger(k, CERTAINTY, new SecureRandom());
            }while (p_prime.compareTo(q_prime)==0);
            q = (q_prime.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE));

        }while (!q.isProbablePrime(CERTAINTY));

        BigInteger n = p.multiply(q);
        BigInteger nsquare = n.pow(2);
        // A generator of group Z_star_nsquare
        BigInteger g = n.add(BigInteger.ONE);
        BigInteger lambda = p_prime.multiply(BigInteger.valueOf(2)).multiply(q_prime);
        //mu = (L(g^lambda mod n^2)) ^ {-1} mod n
        BigInteger mu = Lfunction(g.modPow(lambda, nsquare), n).modInverse(n);

        this.publicKey = new PublicKey(n, g);
        this.privateKey = new PrivateKey(lambda, mu);

    }

    public static BigInteger encrypt (BigInteger m, PublicKey publicKey) throws Exception{
        BigInteger n = publicKey.getN();
        BigInteger nsquare = n.pow(2);
        BigInteger g = publicKey.getG();
        if(!belongToZStarN(m, n)) {
            throw new Exception("Paillier.encrypt(BigInteger m, PublicKey"+
                   " pubkey): plaintext m is not"+
            "in Z*_n");
        }
        BigInteger r = randomZStarN(n);
        return (g.modPow(m, nsquare).multiply(r.modPow(n, nsquare))).mod(nsquare);
    }

    // decrypt
    public static BigInteger decrypt(BigInteger c, PublicKey publicKey, PrivateKey privateKey) throws Exception{
        BigInteger n = publicKey.getN();
        BigInteger nsquare = n.pow(2);
        BigInteger g = publicKey.getG();
        BigInteger lambda = privateKey.getLambda();
        BigInteger mu = privateKey.getMu();
        if (!belongToZStarNSquare(c, nsquare)){
            throw new Exception("Paillier.decrypt(BigInteger c, PrivateKey"+
                    "prikey): ciphertext c is not in Z*_(n^2)");
        }
        return Lfunction(c.modPow(lambda, nsquare), n).multiply(mu).mod(n);

    }

    // add
    public static BigInteger add(BigInteger c1, BigInteger c2, PublicKey publicKey){
        BigInteger nsquare = publicKey.getN().pow(2);
        return c1.multiply(c2).mod(nsquare);
    }

    //multiplication
    public static BigInteger mul(BigInteger c, BigInteger m, PublicKey publicKey){
        BigInteger nsquare = publicKey.getN().pow(2);
        return c.modPow(m, nsquare);
    }

    // selfBlind
    public static BigInteger selfBlind(BigInteger c, BigInteger r, PublicKey publicKey){
        BigInteger n = publicKey.getN();
        BigInteger nsquare = n.pow(2);
        return c.multiply(r.modPow(n, nsquare)).mod(nsquare);
    }
    // Lfunction
    private static BigInteger Lfunction(BigInteger mu, BigInteger n){
        return mu.subtract(BigInteger.ONE).divide(n);
    }

    // randomZStarN
    public static BigInteger randomZStarN(BigInteger n){
        BigInteger r;
        do{
            r = new BigInteger(n.bitLength(), new SecureRandom());

        }while(r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);
        return r;
    }

    /**
     * @Title belongToZStarN
     * @Description This function is to test whether the plaintext belongs to Z*_n
     * @param m
     * @param n
     * @return boolean If it is true, the plaintext is Z*_n, otherwise, not
     */
    private static boolean belongToZStarN(BigInteger m, BigInteger n){
        return m.compareTo(BigInteger.ZERO) >= 0 && m.compareTo(n) < 0 && m.gcd(n).intValue() == 1;
    }

    private static boolean belongToZStarNSquare(BigInteger c, BigInteger nsquare){
        return c.compareTo(BigInteger.ZERO) >= 0 && c.gcd(nsquare).intValue()==1
                && c.compareTo(nsquare) < 0;
    }


}
