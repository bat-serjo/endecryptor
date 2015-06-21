package endecryptor;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

import endecryptor.Main.*;
import org.bouncycastle.jce.provider.*;


public class Main {


    private class Operation{
        protected KeyStore keyStore;
        protected String alias;
        protected String storePass;
        protected String inFile;
        protected String outFile;

        protected FileInputStream in;
        protected FileOutputStream out;
        
        public void init(
                KeyStore keyStore,
                String alias,
                String storePass,
                String inFile,
                String outFile) throws Exception {

            this.keyStore = keyStore;
            this.alias = alias;
            this.storePass = storePass;
            this.inFile = inFile;
            this.outFile = outFile;
        }
        
        public void execute() throws Exception{}
    }



    private class HashDigest extends Operation{
        protected String algo;
        protected MessageDigest md;

        public HashDigest(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            md = MessageDigest.getInstance(algo);
         }

        @Override
        public void execute() throws Exception {
            int nread = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            while ((nread = in.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            }
       
            out.write(md.digest());

            in.close();
            out.close();
        }
    }


    


    private class Sign extends Operation{
        protected Signature sig;
        protected String algo;

        public Sign(){}
        
        public Sign(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            sig = Signature.getInstance(algo);
        }

        @Override
        public void execute() throws Exception {
            int nread = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            sig.initSign((PrivateKey)keyStore.getKey(alias, storePass.toCharArray()));
            
            while ((nread = in.read(dataBytes)) != -1) {
                sig.update(dataBytes, 0, nread);
            }
            
            byte[] signature = sig.sign();
            out.write(signature);
            
            System.out.println( sig.getProvider().getInfo() );
            System.out.println( "\nSignature:" + new String(signature, "UTF8") );

            in.close();
            out.close();
        }

    }



    private class Veri extends Sign {
        public FileInputStream dataFile;

        public Veri(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            sig = Signature.getInstance(algo);
            
        }
        
        @Override
        public void execute() throws Exception {
            int nread = 0;
            byte[] dataBytes = new byte[1024];
            ByteArrayOutputStream signature = new ByteArrayOutputStream();

            in = new FileInputStream(inFile);
            dataFile = new FileInputStream(outFile);
            
            sig.initVerify( keyStore.getCertificate(alias).getPublicKey() );

            while ((nread = in.read(dataBytes)) != -1) {
                signature.write(dataBytes, 0, nread);
            }
            
            nread = 0;
            while ((nread = dataFile.read(dataBytes)) != -1) {
                sig.update(dataBytes, 0, nread);
            }
            
            if (sig.verify(signature.toByteArray()))
                System.out.println( "Signature verified" );
             else
                System.out.println( "Signature failed" );

            in.close();
            dataFile.close();
        }
    }


    private class BlockEncrypt extends Operation {
        protected String algo;
        protected Cipher cp;

        public BlockEncrypt(){}
        public BlockEncrypt(String algo){
            this.algo = algo;
        }
        
        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            cp = Cipher.getInstance(algo);
            cp.init(Cipher.ENCRYPT_MODE, keyStore.getKey(alias, storePass.toCharArray()));
        }

        @Override
        public void execute() throws Exception {
            int bt = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            CipherInputStream cIn = new CipherInputStream(in, cp);

            while ((bt = cIn.read()) > 0) {
                out.write(bt);
            }            

            cIn.close();
            in.close();
            out.close();
        }
    }

    private class BlockDecrypt extends BlockEncrypt {

        public BlockDecrypt(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            cp = Cipher.getInstance(algo);
            cp.init(Cipher.DECRYPT_MODE, keyStore.getKey(alias, storePass.toCharArray()));
        }

        @Override
        public void execute() throws Exception {
            int nbytes = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            CipherOutputStream cout = new CipherOutputStream(out, cp);

            while ((nbytes = in.read(dataBytes)) != -1) {
                cout.write(dataBytes, 0, nbytes);
            }

            cout.close();
            in.close();
            out.close();
        }
    }



    private class AsymEncrypt extends Operation {
        protected String algo;
        protected Cipher cp;

        public AsymEncrypt(){}
        public AsymEncrypt(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            cp = Cipher.getInstance(algo);
            cp.init(Cipher.ENCRYPT_MODE, keyStore.getCertificate(alias).getPublicKey());
        }

        @Override
        public void execute() throws Exception {
            int bt = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            CipherInputStream cIn = new CipherInputStream(in, cp);

            while ((bt = cIn.read()) > 0) {
                out.write(bt);
            }

            cIn.close();
            in.close();
            out.close();
        }
    }

    private class AsymDecrypt extends AsymEncrypt {

        public AsymDecrypt(String algo){
            this.algo = algo;
        }

        @Override
        public void init(
                        KeyStore keyStore,
                        String alias,
                        String storePass,
                        String inFile,
                        String outFile) throws Exception{

            super.init(keyStore, alias, storePass, inFile, outFile);
            cp = Cipher.getInstance(algo);
            cp.init(Cipher.DECRYPT_MODE, (PrivateKey)keyStore.getKey(alias, storePass.toCharArray()));
        }

        @Override
        public void execute() throws Exception {
            int nbytes = 0;
            byte[] dataBytes = new byte[1024];

            in = new FileInputStream(inFile);
            out = new FileOutputStream(outFile);

            CipherOutputStream cout = new CipherOutputStream(out, cp);

            while ((nbytes = in.read(dataBytes)) != -1) {
                cout.write(dataBytes, 0, nbytes);
            }

            cout.close();
            in.close();
            out.close();
        }
    }




    HashMap<String, Operation> ops = new HashMap<String, Operation>();

    public Main(){
        this.ops.put("SHA-1" , new HashDigest("SHA-1"));
        this.ops.put("SHA-256" , new HashDigest("SHA-256"));
        this.ops.put("SHA-384" , new HashDigest("SHA-384"));
        this.ops.put("SHA-512" , new HashDigest("SHA-512"));
        this.ops.put("MD2", new HashDigest("MD2"));
        this.ops.put("MD5", new HashDigest("MD5"));

        this.ops.put("MD2withRSA-Sign", new Sign("MD2withRSA"));
        this.ops.put("MD2withRSA-Veri", new Veri("MD2withRSA"));
        this.ops.put("MD5withRSA-Sign", new Sign("MD5withRSA"));
        this.ops.put("MD5withRSA-Veri", new Veri("MD5withRSA"));
        this.ops.put("SHA1withRSA-Sign", new Sign("SHA1withRSA"));
        this.ops.put("SHA1withRSA-Veri", new Veri("SHA1withRSA"));

        this.ops.put("AESCrypt", new BlockEncrypt("AES"));
        this.ops.put("AESDecrypt", new BlockDecrypt("AES"));
        this.ops.put("BlowfishCrypt", new BlockEncrypt("Blowfish"));
        this.ops.put("BlowfishDecrypt", new BlockDecrypt("Blowfish"));
        this.ops.put("RC2Crypt", new BlockEncrypt("RC2"));
        this.ops.put("RC2Decrypt", new BlockDecrypt("RC2"));
        this.ops.put("RC4Crypt", new BlockEncrypt("RC4"));
        this.ops.put("RC4Decrypt", new BlockDecrypt("RC4"));
        this.ops.put("RC5Crypt", new BlockEncrypt("RC5"));
        this.ops.put("RC5Decrypt", new BlockDecrypt("RC5"));
        
        this.ops.put("RSACrypt", new AsymEncrypt("RSA"));
        this.ops.put("RSADecrypt", new AsymDecrypt("RSA"));
    }


    public void evaluate(String keyStore,
                    String alias,
                    String pass,
                    String in,
                    String op,
                    String out) throws Exception {

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(keyStore), pass.toCharArray());

        usage();
        this.ops.get(op).init(keystore, alias, pass, in, out);
        ops.get(op).execute();
        
    }

    public String usage(){
        Set<String> keys = ops.keySet();
        ArrayList<String> strKeys = new ArrayList<String>();
        StringBuilder ret = new StringBuilder();

        for (String s: keys){
            strKeys.add(s);
        }
        
        Collections.sort(strKeys);

        ret.append("\nUSAGE: All parameters mendatory!\n\n");
        ret.append("[keytool store] [alias] [password] [input file] [operation] [output file]\n");
        ret.append("\n[ OPERATIONS ]\n");

        for (String s: strKeys){
            ret.append('\t').append(s).append('\n');
        }
        
        ret.append("\n");

        return ret.toString();
    }



    
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Main m = new Main();

        try{
            m.evaluate(args[0], args[1], args[2], args[3], args[4], args[5]);
        }catch(Exception e){
            System.out.print(m.usage());
            System.out.print(e.toString()+'\n');
        }
    }
}
