package org.pke;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Scanner;

import jdk.jshell.JShell;
import org.pke.BGN;
import org.pke.SHE;


public class Main {
    public static void main(String[] args) throws Exception {
        // Scanner scanner = new Scanner(System.in);
/*        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Please input which PKE you want to test");
        System.out.println("1.Paillier,  2.BGN");
        while(true) {
            String selection = br.readLine();
            if (selection.equals("1") || selection.equals("Paillier"))
            {
                testPaillier();
                break;
            }
            if (selection.equals("2") || selection.equals("BGN"))
            {
                testBGN();
                break;
            }
            else
                System.out.println("Illegal input!");
        }*/
        SHE she = new SHE();
        she.keyGeneration(1024, 10, 80);
        SHE.PublicKey publicKey = she.getPublicKey();
        SHE.PrivateKey privateKey = she.getPrivateKey();

        BigInteger message = BigInteger.valueOf(-180);
        BigInteger cipherText = BigInteger.valueOf(0);
        BigInteger decryptText = BigInteger.valueOf(0);

        try{
            cipherText = SHE.encrypt(message, publicKey, privateKey);
            decryptText = SHE.decrypt(cipherText, publicKey, privateKey);
        }catch (Exception e){
            e.printStackTrace();
            return;
        }
        System.out.println("Message is: " + message);
        System.out.println("CipherText is: " + cipherText);
        System.out.println("DecryptText is: " + decryptText);

        // Simple encryption and Decryption
        if (decryptText.compareTo(message) == 0){
            System.out.println("Encryption and Decryption tests successfully");
        }

        // Homomorphic addition-I
        BigInteger message1 = BigInteger.valueOf(123);
        BigInteger message2 = BigInteger.valueOf(-321);

        BigInteger cipher1 = BigInteger.valueOf(0);
        BigInteger cipher2 = BigInteger.valueOf(0);

        BigInteger mes1addmes2 = BigInteger.valueOf(0);
        BigInteger decmes1addmes2 = BigInteger.valueOf(0);
        try {
            cipher1 = SHE.encrypt(message1, publicKey, privateKey);
            cipher2 = SHE.encrypt(message2, publicKey, privateKey);

            mes1addmes2 = message1.add(message2);
            decmes1addmes2 = SHE.decrypt(cipher1.add(cipher2), publicKey, privateKey);
        }catch (Exception e){
            e.printStackTrace();
        }
        if(decmes1addmes2.equals(mes1addmes2)){
            System.out.println("Homomorphic addition-I tests successfully.");
        }

        // Homomorphic multiplication-I
        BigInteger mes1mulmes2 = message1.multiply(message2);
        BigInteger deccipher1mulcipher2 = BigInteger.valueOf(0);
        try {
            // mes1mulmes2 = message1.multiply(message2);
            deccipher1mulcipher2 = SHE.decrypt(cipher1.multiply(cipher2), publicKey, privateKey);
        }catch (Exception e){
            e.printStackTrace();
        }
        if(deccipher1mulcipher2.equals(mes1mulmes2)){
            System.out.println("Homomorphic multiplication-I tests successfully.");
        }

        // Homomorphic addition-II
        BigInteger deccipher1addmes2 = BigInteger.valueOf(0);
        try{
            deccipher1addmes2 = SHE.decrypt(cipher1.add(message2), publicKey, privateKey);
        }catch (Exception e){
            e.printStackTrace();
        }
        if(mes1addmes2.equals(deccipher1addmes2)){
            System.out.println("Homomorphic addition-II tests successfully.");
        }

        // Homomorphic multiplication-II
        BigInteger deccipher1mulmes2 = BigInteger.valueOf(0);
        try{
            deccipher1mulmes2 = SHE.decrypt(cipher1.multiply(message2), publicKey, privateKey);
        }catch (Exception e){
            e.printStackTrace();
        }
        if (deccipher1mulmes2.equals(mes1mulmes2)){
            System.out.println("Homomorphic multiplication-II tests successfully.");
        }

    }
    public static void testPaillier()
    {
        Paillier paillier = new Paillier();

        // KeyGeneration
        paillier.keyGeneration(512);
        Paillier.PublicKey publicKey = paillier.getPublicKey();
        Paillier.PrivateKey privateKey = paillier.getPrivateKey();

        //Encryption and Decryption
        byte[] stringBytes = new String("ee").getBytes() ;
        BigInteger m = new BigInteger(new String("ee").getBytes());
        BigInteger c = BigInteger.valueOf(0);
        BigInteger decrypted_m = BigInteger.valueOf(0);
        try{
            c = Paillier.encrypt(m, publicKey);
            decrypted_m = Paillier.decrypt(c, publicKey, privateKey);
        } catch (Exception e){
            e.printStackTrace();
        }

        if (decrypted_m.compareTo(m) == 0){
            System.out.println("Encryption and Decryption test successfully");
        }

        // Homomorphic Properties

        // Addition
        BigInteger m1 = new BigInteger("12345");
        BigInteger m2 = new BigInteger("56789");

        BigInteger m1plusm2 = m1.add(m2);

        try{
            BigInteger c1 = Paillier.encrypt(m1, publicKey);
            BigInteger c2 = Paillier.encrypt(m2, publicKey);
            BigInteger c1mulc2 = Paillier.add(c1, c2, publicKey);
            BigInteger decryptedC1MulC2 =
                    Paillier.decrypt(c1mulc2, publicKey, privateKey);
            if (decryptedC1MulC2.compareTo(m1plusm2) == 0){
                System.out.println("Homomorphic addition tests successfully");
            }
        } catch (Exception e){
            e.printStackTrace();
        }

        // Multiplication
        m1 = new BigInteger("12345");
        m2 = new BigInteger("56789");
        BigInteger m1mulm2 = m1.multiply(m2);
        try{
            BigInteger c1 = Paillier.encrypt(m1, publicKey);
            BigInteger c1expm2 = Paillier.mul(c1, m2, publicKey);
            BigInteger decryptedC1ExpM2 =
                    Paillier.decrypt(c1expm2, publicKey, privateKey);
            if (decryptedC1ExpM2.compareTo(m1mulm2) == 0){
                System.out.println("Homomorphic multiplication tests successfully.");
            }
        } catch (Exception e){
            e.printStackTrace();
        }

        // Self-Blinding
        m1 = new BigInteger("12345");
        BigInteger r2 = Paillier.randomZStarN(publicKey.getN());
        try{
            BigInteger c1 = Paillier.encrypt(m1, publicKey);
            BigInteger c1mulrn = Paillier.selfBlind(c1, r2, publicKey);
            BigInteger decryptedC1MulRn = Paillier.decrypt(c1mulrn, publicKey, privateKey);
            if (decryptedC1MulRn.compareTo(m1) == 0){
                System.out.println("Homomorphic self-blinding tests successfully");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void testBGN()
    {
        BGN bgn = new BGN();

        // Key generation
        bgn.keyGeneration(512);
        BGN.PublicKey publicKey = bgn.getPublicKey();
        BGN.PrivateKey privateKey = bgn.getPrivateKey();

        //Encryption and Decryption
        int m = 10;
        Element c = null;
        int decryptedM = 0;
        try{
            c = BGN.encrypt(m, publicKey);
            decryptedM = BGN.decrypt(c, publicKey, privateKey);

        }
        catch(Exception e){
            e.printStackTrace();
        }
        if(decryptedM == m){
            System.out.println("Encryption and Decryption "+
                    "tests successfully");
        }

        // Homomorphic Properties
        // Addition
        int m1 = 5;
        int m2 = 6;
        try{
            Element c1 = BGN.encrypt(m1, publicKey);
            Element c2 = BGN.encrypt(m2, publicKey);
            Element c1MulC2 = BGN.add(c1, c2);
            int decryptedC1MulC2 = BGN.decrypt(c1MulC2, publicKey, privateKey);
            if(decryptedC1MulC2 == (m1 + m2)){
                System.out.println("Homomorphic addition tests successfully.");
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }

        // multiplication-1
        m1 = 5;
        m2 = 6;
        try{
            Element c1 = BGN.encrypt(m1, publicKey);
            Element c1expm2 = BGN.mul1(c1, m2);
            int decryptedC1expm2 = BGN.decrypt(c1expm2, publicKey, privateKey);
            if (decryptedC1expm2 == (m1 * m2)){
                System.out.println("Homomorphic multiplication-1 tests successfully");
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }

        // multiplication-2
        m1 = 5;
        m2 = 6;
        try{
            Element c1 = BGN.encrypt(m1, publicKey);
            Element c2 = BGN.encrypt(m2, publicKey);
            Element c1pairingc2 = publicKey.getPairingE().pairing(c1, c2).getImmutable();
            int decryptedC1pairingc2 = BGN.decryptMul2(c1pairingc2, publicKey, privateKey);
            if(decryptedC1pairingc2 == (m1 * m2)){
                System.out.println("Homomorphic multiplication-2 tests successfully");
            }

        }
        catch (Exception e){
            e.printStackTrace();
        }

        // self-Blinding
        m1 = 5;
        try{
            BigInteger r2 = publicKey.getPairingE().getZr().newRandomElement().toBigInteger();
            Element c1 = BGN.encrypt(m1, publicKey);
            Element c1_selfBlind =BGN.selfBlind(c1, r2, publicKey);
            int decryptedC1Selfblind = BGN.decrypt(c1_selfBlind, publicKey, privateKey);
            if (decryptedC1Selfblind == m1){
                System.out.println("Homomorphic self-blinding"
                                    + "tests successfully.");
            }

        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}