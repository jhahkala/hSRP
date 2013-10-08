package fi.hip.sicx.srp;

import java.math.BigInteger;

/**
 * The generated parameters for the SRP protocol.
 * 
 * @author hahkala
 *
 */
public class Params {
    
    /**
     * The hex string of the safe prime used as modulus. Generated with openssl dhparam
     */
    public static final String NString = 
            "008d296b9e4a3e4f7b20eb164d6f60"+
            "2ab1dd4adbace8197a5fd0d0dc9d80"+
            "b8a9d66433abc5b2f94b0c3accce21"+
            "db1ec6ae59ea333e7644a184bd46a8"+
            "ddf47a611c4119794fdb3741c6f265"+
            "5b8f54ce6c9c64e574b261de6e9136"+
            "6900ff849676f9873dd7004bd28cc6"+
            "3adf558579007c63588199ad7439ec"+
            "3cfa322da3fe508fdfaca6fc9111ed"+
            "0f34c6d7b7cd8c5d27e67cfb8e51c3"+
            "679b1213d0906fe3a3d08b432de8ae"+
            "e56444823408d2e6c3096acfa49338"+
            "a78151cf3dc3aacfd949d925de47fa"+
            "8c4142ace777d0af9fbf63890a8acd"+
            "9861b3893da4d5249f8bc2f067d367"+
            "1ca1b0f31178ec2dded5e3205f58f4"+
            "5bb3bbf2b7a7055bfad3ecb14b044f"+
            "245b";
    /**
     * The safe prime used as modulus.
     */
    public static final BigInteger N = new BigInteger(NString, 16);
    /**
     * The generator for the calculations.
     */
    public static final BigInteger g = BigInteger.valueOf(5);
    
    public static final int bytes = (N.bitLength() + 7)/8;
    
    public static final BigInteger zero = new BigInteger("0");
    
    public static final byte zeroBytes[] = SRPUtil.getPadded(zero, bytes);
}
