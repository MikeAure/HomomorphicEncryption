package org.pke;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SHE {

    public class PublicKey{
        private int k0;
        private int k1;
        private int k2;
        private BigInteger p, q, N;

        public PublicKey(int k0, int k1, int k2, BigInteger p, BigInteger q){
            this.k0 = k0;
            this.k1 = k1;
            this.k2 = k2;
            this.p = p;
            this.q = q;
            this.N = p.multiply(q);

        }

        public int getK0() {
            return k0;
        }

        public int getK1() {
            return k1;
        }

        public int getK2(){
            return k2;
        }

        public BigInteger getN() {
            return N;
        }

        public BigInteger getP() {
            return p;
        }

        public BigInteger getQ() {
            return q;
        }
    }

    public class PrivateKey{
        private BigInteger p, L;

        public PrivateKey(BigInteger p, BigInteger L){
            this.p = p;
            this.L = L;
        }

        public BigInteger getP() {
            return p;
        }

        public BigInteger getL() {
            return L;
        }


    }

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private static final int CERTAINTY = 80;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void keyGeneration(int k0, int k1, int k2) throws Exception{

        BigInteger p, q, L;
        if(!(2 * k1 < k2 && k2 < k0)){
            throw new Exception("Illegal secure parameters!");
        }

        p = new BigInteger(k0, CERTAINTY, new SecureRandom());

        do{
            q = new BigInteger(k0, CERTAINTY, new SecureRandom());
        }while(p.equals(q));

        this.publicKey = new PublicKey(k0, k1, k2, p, q);

        L = new BigInteger(k2, CERTAINTY, new SecureRandom());

        this.privateKey = new PrivateKey(p, L);

    }

    public static BigInteger encrypt(BigInteger m, PublicKey publicKey, PrivateKey privateKey)
            throws Exception{

        int k1 = publicKey.getK1();
        int k2 = publicKey.getK2();
        int k0 = publicKey.getK0();
        BigInteger N = publicKey.getN();
        BigInteger L = privateKey.getL();
        BigInteger p = privateKey.getP();

        if (!judgeMessageSize(m ,k1)) throw new Exception("Illegal message range!");
        BigInteger r = new BigInteger(k2, CERTAINTY, new SecureRandom());
//        System.out.println("Random r is: " + r);
        BigInteger r_plus = new BigInteger(k0, CERTAINTY, new SecureRandom());
//        System.out.println("Random r_plus is: " + r_plus);
        BigInteger cipherText = ((r.multiply(L).add(m)).multiply(r_plus.multiply(p).add(BigInteger.ONE))).mod(N);
        return cipherText;
    }

    public static BigInteger decrypt(BigInteger c, PublicKey publicKey, PrivateKey privateKey){
        BigInteger L = privateKey.getL();
        BigInteger p = privateKey.getP();
        BigInteger message_plus = (c.mod(p)).mod(L);
        BigInteger message = message_plus;

        if(message_plus.compareTo(L.divide(BigInteger.TWO)) > 0){
            message = message_plus.subtract(L);
        }
        return message;
    }

    // public static BigInteger multiplication1(BigInteger c1, BigInteger c2, )
    private static boolean judgeMessageSize(BigInteger m, int k1){
        BigInteger least = BigInteger.valueOf(2).pow(k1 - 1).multiply(BigInteger.valueOf(-1));
        BigInteger most = BigInteger.valueOf(2).pow(k1 - 1);
        return m.compareTo(least) >= 0 &&
                m.compareTo(most) < 0;
    }


}
