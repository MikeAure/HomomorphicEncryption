package org.pke;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

import java.math.BigInteger;

public class BGN {
    /**
     * @ClassName: PublicKey
     * @Description: A class for storing the public key (n, G, GT, e, g, h) of BGN PKE
     */
    public class  PublicKey{
        private BigInteger n;
        private Field<Element> fieldG, fieldGT;
        private Pairing pairingE;
        private Element g, h;
        
        public PublicKey(BigInteger n, Field<Element> G, 
                         Field<Element> GT, Pairing pairing, Element g,
                         Element h){
            this.n = n;
            this.fieldG = G;
            this.fieldGT = GT;
            this.pairingE = pairing;
            this.g = g;
            this.h = h;
        }

        public Element getG() {
            return g;
        }

        public Element getH(){
            return h;
        }

        public BigInteger getN(){
            return n;
        }

        public Pairing getPairingE(){
            return pairingE;
        }

        public Field<Element> getFieldG(){
            return fieldG;
        }

        public Field<Element> getFieldGT(){
            return fieldGT;
        }
    }

    public class PrivateKey{
        private BigInteger p;

        public PrivateKey(BigInteger p){
            this.p = p;
        }

        public BigInteger getP(){
            return p;
        }

    }

    private static int T = 100;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * @Title: keyGeneration
     * @Description: This function is responsible for
     * generating the public key tuple and the private key.
     * @param: k
     *              the security parameter, which decides the length of two large prime p and q.
     * @return void
     */
    public void keyGeneration(int k){
        TypeA1CurveGenerator compositePairingGenerator = new
                TypeA1CurveGenerator(2, k);
        PairingParameters pairingParameters = compositePairingGenerator.generate();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        BigInteger n = pairingParameters.getBigInteger("n");
        BigInteger q = pairingParameters.getBigInteger("n0");
        BigInteger p = pairingParameters.getBigInteger("n1");
        Field<Element> fieldG = pairing.getG1();
        Field<Element> fieldGT = pairing.getGT();
        Element g = fieldG.newRandomElement().getImmutable();
        Element h = g.pow(q).getImmutable();

        this.publicKey = new PublicKey(n, fieldG, fieldGT, pairing, g, h);
        this.privateKey = new PrivateKey(p);
    }

    public PublicKey getPublicKey(){
        return this.publicKey;
    }

    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }

    public static Element encrypt(int m, PublicKey publicKey) throws Exception{
        if (m > T){
            throw new Exception(
                    "BGN.encrypt(int m, PublicKey publicKey): "
                    + "plaintext m is not in [0, 1, 2 ... ,"
                    + T + "]");
        }
        Pairing pairing = publicKey.getPairingE();
        Element g = publicKey.getG();
        Element h = publicKey.getH();
        BigInteger r = pairing.getZr().newRandomElement().toBigInteger();
        return g.pow(BigInteger.valueOf(m)).mul(h.pow(r))
                .getImmutable();
    }

    public static int decrypt(Element c, PublicKey publicKey,
                              PrivateKey privateKey) throws Exception{
        BigInteger p = privateKey.getP();
        Element g = publicKey.getG();
        Element cp = c.pow(p).getImmutable();
        Element gp = g.pow(p).getImmutable();
        for(int i = 0; i <= T; i++){
            if(gp.pow(BigInteger.valueOf(i)).isEqual(cp)){
                return i;
            }
        }
        throw new Exception(
                "BGN.decrypt(Element c, PublicKey publicKey, PrivateKey privatekey):"
                + "plaimtext m is not in [0, 1, 2,...,"
                + T + "]"
        );
    }

    public static int decryptMul2(Element c, PublicKey publicKey,
                                   PrivateKey privateKey) throws Exception{
        BigInteger p = privateKey.getP();
        Element g = publicKey.getG();
        Element cp = c.pow(p).getImmutable();
        Element egg = publicKey.getPairingE().pairing(g, g).pow(p).getImmutable();
        for (int i = 0; i <= T; i++){
            if(egg.pow(BigInteger.valueOf(i)).isEqual(cp)){
                return i;
            }
        }

        throw new Exception("BGN.decrypt(Element c, PublicKey pubkey,"
                + "PrivateKey prikey): "
                + "plaintext m is not in [0,1,2,...,"
                + T + "]");
    }

    public static Element add(Element c1, Element c2){
        return c1.mul(c2).getImmutable();
    }

    public static Element mul1(Element c1, int m2){
        return c1.pow(BigInteger.valueOf(m2)).getImmutable();
    }

    /**
     * @Title mul2
     * @Description The function supports the homomorphic multiplication with one ciphertext
     *              and one ciphertext
     * @param c1
     * @param c2
     * @param publicKey
     * @return
     */
    public static Element mul2(Element c1, Element c2, PublicKey publicKey){
        Pairing pairing = publicKey.getPairingE();
        return pairing.pairing(c1, c2).getImmutable();
    }

    /**
     * @Title selfBlind
     * @Description The function supports the homomorphic self-blinding with one ciphertext
     *              and one random number.
     * @param c1
     * @param r2
     * @param publicKey
     * @return Element the return value is c1*h*r2
     */
    public static Element selfBlind(Element c1, BigInteger r2, PublicKey publicKey){
        Element h = publicKey.getH();
        return c1.mul(h.pow(r2)).getImmutable();
    }

}
