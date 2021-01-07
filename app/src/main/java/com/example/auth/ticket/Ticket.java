package com.example.auth.ticket;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Ticket {

    private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key

    /**
     * TODO: Change these according to your design. Diversify the keys.
     */
    private static byte[] authenticationKey = defaultAuthenticationKey;// 16-byte key21

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = true;
    private int remainingUses;
    final private int maximumCappedIssues = 500;
    String pattern = "yyyy/MM/dd HH:mm:ss";
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
    Date date;

    {
        try {
            date = simpleDateFormat.parse("2021/12/29 15:30:00");
            Utilities.log("Max Capped LifeTime for the Card:" + date, false);
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    final private long maximumCappedExpirationTime = (long) date.getTime();
    private int expiryTime = 0;
    private byte[] appTagAndVersion = "NFCT0001".getBytes();
    private int expiryValidityInMins = 2;


    final private int pageForTagAndVersionStart = 0x04;
    final private int pageForMaxRideATM = 0x06;
    final private int pageForExpirationTime = 0x07;
    final private int pageForMACStartOdd = 0x0A;
    final private int pageForMACStartEven = 0x10;
    final private int pageForCounter = 0x29;

    private static String infoToShow; // Use this to show messages

    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        String tmp = infoToShow;
        infoToShow = "Validated";
        return tmp;
    }

    public static byte[] getUIDInBytes() {
        byte[] uidBytes = Reader.nfcA_card.getTag().getId();
        return uidBytes;
    }

    public static String convertByteArrayToString(byte[] input) {
        if (input == null) {
            return null;
        }
        StringBuilder hex = new StringBuilder(input.length * 2);
        for (byte b : input) {
            hex.append(Integer.toHexString(b & 0xFF));
        }
        return hex.toString();
    }

    public static int convertByteArrayToInt(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getInt();
    }

    public static byte[] convertIntToByteArray(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    public static byte[] calculateDiversifiedAuthKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final int keyLength = 128; //in bits
        final int iterationCount = 1000;

        final byte[] salt = "NETSECPROJECT123".getBytes();

        KeySpec spec = new PBEKeySpec(convertByteArrayToString(getUIDInBytes()).toCharArray(), salt, iterationCount, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    public int getRemainingUses() {
        return remainingUses;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * Issue new tickets
     * <p>
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        boolean firstIssue = false;
        boolean cardNotActivated = false;
        boolean expiredCard = false;

        //TODO: remove, can be uncommented for the purpose of resetting the card to default key
//        if(resetCard()){
//            return true;
//        }

        // Authenticate
        res = utils.authenticate(defaultAuthenticationKey);
        if (res) {
            //if card has the default authentication key, the card is to be issued for the very first time
            firstIssue = true;
            infoToShow = "The card is being issued for the first time";
            Utilities.log(infoToShow, false);
            if (utils.eraseMemory()) {
                infoToShow = "All Memory Erased to reset the card";
                Utilities.log(infoToShow, true);
            } else {
                Utilities.log("Card could not be reset", true);
                return false;
            }
            Utilities.log("Card is getting issued for the very first time", false);
            final byte[] NEWKEY = calculateDiversifiedAuthKey();
            authenticationKey = NEWKEY;
            res = utils.writePages(authenticationKey, 0, 0x2C, 4);
            if (!res) {
                infoToShow = "Error encountered while writing the new authentication key";
                Utilities.log(infoToShow, true);
                return false;
            }
            //write the application tag and version
            res = utils.writePages(appTagAndVersion, 0, pageForTagAndVersionStart, 2);
            if (!res) {
                infoToShow = "Error encountered while writing the tag and version";
                Utilities.log(infoToShow, true);
                return false;
            }
            //reset the current allowed ride to the counter number of card
            res = utils.writePages(convertIntToByteArray(readCounterValue()), 0, pageForMaxRideATM, 1);
            if (!res) {
                infoToShow = "Error encountered while configuring the number of initial rides to 0";
                Utilities.log(infoToShow, true);
                return false;
            }


        } else {
            //if the card does not have the default authentication key
            infoToShow = "Authentication did not succeed using default key, checking with the configured key";
            Utilities.log(infoToShow, true);

            // Authenticate using the set auth key in the card
            res = utils.authenticate(calculateDiversifiedAuthKey());
            if (res) {
                infoToShow = "Authenticated using the set key in the card";
                Utilities.log(infoToShow, false);
            } else {
                infoToShow = "Could not be authenticated with either the default key or the set key";
                Utilities.log(infoToShow, true);
                return false;
            }

            //Check MAC
            if (!checkMac()) {
                return false;
            }

            expiryTime = readExpirationTime();
            if (expiryTime == 0) {
                cardNotActivated = true;
            } else if (expiryTime == -1) {
                Utilities.log("Could not read expiration time", true);
                return false;
            }
        }

        //enable Memory Protection
        if (!enableAuth0() || !enableReadWriteRestriction()) {
            infoToShow = "Error encountered during memory protection.";
            Utilities.log(infoToShow, true);
            return false;
        }


        expiryTime = readExpirationTime();
        if(expiryTime == -1){
            Utilities.log("Could not read the expiration time", true);
            return false;
        }
        int currentTime = (int) ((new Date()).getTime() / 1000);
        if (expiryTime != 0) {
            if (expiryTime < currentTime) {
                expiryTime = currentTime + (expiryValidityInMins * 60);
                expiredCard = true;
            } else {
                expiryTime += (expiryValidityInMins * 60);
                if (expiryTime > maximumCappedExpirationTime) {
                    infoToShow = "Cannot increase the expiration Time anymore. The life of the card is dead.";
                    Utilities.log(infoToShow, true);
                    return false;
                }
            }
            Date expirationDate = new Date((long) expiryTime * 1000);
            Utilities.log("Max LifeTime of the Card: " + new Date((long) maximumCappedExpirationTime), false);
            byte[] expirationTimeInBytes = convertIntToByteArray(expiryTime);
            res = utils.writePages(expirationTimeInBytes, 0, pageForExpirationTime, 1);
            if (!res) {
                Utilities.log("Could not write the expiration time", true);
                return false;
            }
            Utilities.log("Expiration set to: " + expirationDate, false);
        }


        if (cardNotActivated) {
            //if expiry time is still 0, do not issue more yet
            infoToShow = "The card has already been issued for the first time.\nPlease use and activate the card before this card can be issued again";
            Utilities.log(infoToShow, true);
            return false;
        }


        //read max rides allowed for the card with respect to the counter value
        int maxRideAllowedForTheCard = readMaxRideForTheCard();

        //read counter from card
        int counterIntValue = readCounterValue();

        //write new number of allowed rides until next issue

        Utilities.log("Max ride remaining: " + maxRideAllowedForTheCard, false);
        int newRideLimitsAfterIssue = maxRideAllowedForTheCard + 5;
        if (newRideLimitsAfterIssue > maximumCappedIssues) {
            infoToShow = "Cannot issue any more rides to this card. The life of the card is dead.";
            Utilities.log(infoToShow, true);
            return false;
        }

        res = utils.writePages(convertIntToByteArray(newRideLimitsAfterIssue), 0, pageForMaxRideATM, 1);
        if (!res) {
            Utilities.log("Could not issue tickets. Retry Again.", false);
            return false;
        }
        Utilities.log("New Rides Total subject to counter decrement: " + newRideLimitsAfterIssue, false);
        //calculate HMAC using UID, appTagAndVersion, maxAllowedRideForCard and authenticationKey
        byte[] mac = calculateMAC(authenticationKey, convertIntToByteArray(expiryTime));

        Utilities.log("MAC Calculated ", false);
        res = writeMAC(mac, counterIntValue);
        if (res) {
            Utilities.log("MAC written", false);
        } else {
            infoToShow = "Error encountered while trying to write the MAC";
            Utilities.log(infoToShow, false);
            return false;
        }

        remainingUses = newRideLimitsAfterIssue - counterIntValue;
        String additionalInfo = "";
        String additionalPrefix = "";
        if (firstIssue) {
            additionalInfo = "\nThe card will be activated when used for the first time";
        } else {
            //expiryTime = readExpirationTime();
            additionalInfo = "\nExpiring At: " + new Date((long) expiryTime * 1000);
        }
        if (expiredCard) {
            additionalPrefix = "The card has been renewed with additional rides.\n";
        } else {
            additionalPrefix = "Tickets Issued.\n";
        }

        infoToShow = additionalPrefix + "Remaining Rides: " + remainingUses + additionalInfo;
        Utilities.log(infoToShow, false);

        return true;
    }

    /**
     * Use ticket once
     * <p>
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        boolean firstUse = false;

        //Check if the card is default and has not been issued
        res = utils.authenticate(defaultAuthenticationKey);
        if (res) {
            infoToShow = "Card has not been issued.\nPlease have this card issued before using.";
            isValid = false;
            Utilities.log(infoToShow, true);
            return false;
        }

        // Authenticate using the auth Key
        authenticationKey = calculateDiversifiedAuthKey();
        macAlgorithm.setKey(authenticationKey);
        res = utils.authenticate(authenticationKey);
        if (!res) {
            infoToShow = "Could not authenticate the card.";
            isValid = false;
            Utilities.log(infoToShow, true);
            return false;
        } else {
            Utilities.log("Authentication succeeded", false);
        }

        //Check MAC
        if (!checkMac()) {
            isValid = false;
            return false;
        }


        int currentTime = (int) ((new Date()).getTime() / 1000);
        expiryTime = readExpirationTime();
        if (expiryTime == 0) {
            Utilities.log("First use of the card detected", false);
            expiryTime = currentTime + (expiryValidityInMins * 60);
            firstUse = true;
        } else if (expiryTime == -1){
            Utilities.log("Could not read the expiration Time", true);
            return false;
        }

        if (expiryTime < currentTime) {
            infoToShow = "The card has been expired.\nExpired at: " + new Date((long) expiryTime * 1000);
            isValid = false;
            Utilities.log(infoToShow, true);
            return false;
        }
        //read counter from card
        int counterIntValue = readCounterValue();
        if(firstUse){

            byte[] expirationTimeInBytes = convertIntToByteArray(expiryTime);
            byte[] mac = calculateMAC(authenticationKey, expirationTimeInBytes);
            res = writeMAC(mac, counterIntValue + 1);
            if (res) {
                infoToShow = "First time card use configuration ongoing.\nHold the Card for longer.";
                Utilities.log("MAC written", false);
            } else {
                infoToShow = "Error encountered while trying to write the MAC";
                isValid = false;
                Utilities.log(infoToShow, false);
                return false;
            }
            //TODO: remove, check for tearing protection
//            if(true){
//                return true;
//            }

            res = utils.writePages(expirationTimeInBytes, 0, pageForExpirationTime, 1);
            if (!res) {
                infoToShow = "Could not set the expiration Time";
                isValid = false;
                Utilities.log(infoToShow, true);
                return false;
            } else {
                infoToShow = "The card is now activated. The expiration time is set at " + new Date((long) expiryTime * 1000) + "\nHold the card till it is used successfully.";
                Utilities.log(infoToShow, false);
            }
        }
        //read max rides allowed for the card with respect to the counter value
        int maxRideAllowedForTheCard = readMaxRideForTheCard();



        if (counterIntValue >= maxRideAllowedForTheCard) {
            infoToShow = "All rides have been used up.";
            isValid = false;
            Utilities.log(infoToShow, true);
            return false;
        } else {
            //increase counter value
            byte[] counter_data = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            utils.writePages(counter_data, 0, pageForCounter, 1);
            remainingUses = readMaxRideForTheCard() - readCounterValue();
            infoToShow = "Ride validated" + "\n" + "Remaining Rides: " + getRemainingUses() + "\n" + "Expiring at: " + new Date((long) expiryTime * 1000);
            Utilities.log(infoToShow, false);
        }



        return true;
    }

    public boolean writeMAC(byte[] mac, int counterValue) {
        boolean res = false;
        //int counterValue = readCounterValue();
        if(counterValue == -1){
            Utilities.log("Could not read the counter value", true);
            return false;
        }
        if(counterValue%2 == 0){
            res = utils.writePages(mac, 0, pageForMACStartEven, 5);
        }else {
            res = utils.writePages(mac, 0, pageForMACStartOdd, 5);
        }
        return res;
    }

    public byte[]  readMAC(int counterValue) {
        byte[] readMac = new byte[5*4];
        boolean res;
        if(counterValue == -1){
            Utilities.log("Could not read the counter value", true);
            return null;
        }
        if(counterValue%2 == 0){
            res = utils.readPages(pageForMACStartEven,5,readMac, 0);
        }else {
            res = utils.readPages(pageForMACStartOdd,5,readMac, 0);
        }
        if(!res){
            return null;
        }
        return readMac;
    }

    public byte[] calculateMAC(byte[] authenticationKey, byte[] readExpirationTime) throws GeneralSecurityException {
        //calculate HMAC using UID, appTagAndVersion, authenticationKey
        byte[] readUid = getUIDInBytes();
        byte[] readTagnVersion = new byte[2 * 4];
        byte[] readMaximumAllowedRides = new byte[4];
        //byte[] readExpirationTime = new byte[4];
        boolean res = utils.readPages(pageForTagAndVersionStart, 2, readTagnVersion, 0);
        if (!res) {
            infoToShow = "Could not Read the tag and version";
            Utilities.log(infoToShow, false);
            return null;
        }
        res = utils.readPages(pageForMaxRideATM, 1, readMaximumAllowedRides, 0);
        if (!res) {
            infoToShow = "Could not Read the max allowed ride for the card";
            Utilities.log(infoToShow, false);
            return null;
        }
//        res = utils.readPages(pageForExpirationTime, 1, readExpirationTime, 0);
//        if (!res) {
//            infoToShow = "Could not Read the expiration Time";
//            Utilities.log(infoToShow, false);
//            return null;
//        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(readUid);
            outputStream.write(readTagnVersion);
            outputStream.write(readMaximumAllowedRides);
            outputStream.write(readExpirationTime);
            outputStream.write(authenticationKey);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] inputForMac = outputStream.toByteArray();
        macAlgorithm.setKey(authenticationKey);
        return macAlgorithm.generateMac(inputForMac);
    }

    public boolean checkMac() throws GeneralSecurityException {
        //Check MAC
        byte[] readMac;
        int counterValue = readCounterValue();
        readMac = readMAC(counterValue);
        if (readMac == null) {
            infoToShow = "Could not read the MAC pages";
            Utilities.log(infoToShow, true);
            return false;
        }
        //Calculate MAC
        authenticationKey = calculateDiversifiedAuthKey();
        int expirationTime = readExpirationTime();
        if(expirationTime == -1){
            Utilities.log("Could not read expiration time", true);
            return false;
        }
        byte[] mac = calculateMAC(authenticationKey, convertIntToByteArray(expirationTime));
        String macString = convertByteArrayToString(mac);
        String readMacString = convertByteArrayToString(readMac);
        //TODO: remove
        Utilities.log("Checking mac: " + macString + " : " + readMacString, true);
        if (macString != null && readMacString != null && macString.equals(readMacString)) {
            Utilities.log("MAC matches", false);
            return true;
        } else {
            readMac = readMAC(counterValue +1);
            readMacString = convertByteArrayToString(readMac);
            if(readMacString!= null && macString.equals(readMacString)){
                //TODO: remove
                Utilities.log("Tearing occurred in previous transaction. Checking with earlier MAC", true);
                Utilities.log("MAC matches", false);
                return true;
            }else {
                infoToShow = "Failed to validate the card.\nMAC does not match";
                isValid = false;
                Utilities.log(infoToShow, true);
                return false;
            }

        }
    }

    public int readCounterValue() {
        byte[] counterBytes = new byte[4];
        boolean res = utils.readPages(pageForCounter, 1, counterBytes, 0);
        if(!res){
            return -1;
        };
        //reversing counterBytes
        for (int i = 0; i < counterBytes.length / 2; i++) {
            byte temp = counterBytes[i];
            counterBytes[i] = counterBytes[counterBytes.length - i - 1];
            counterBytes[counterBytes.length - i - 1] = temp;
        }

        int counterIntValue = convertByteArrayToInt(counterBytes);
        return counterIntValue;
    }

    public int readMaxRideForTheCard() {
        //read max rides allowed for the card with respect to the counter value
        byte[] maxRideIssuedBytes = new byte[4];
        utils.readPages(pageForMaxRideATM, 1, maxRideIssuedBytes, 0);
        int maxRideAllowedForTheCard = convertByteArrayToInt(maxRideIssuedBytes);
        return maxRideAllowedForTheCard;
    }

    public int readExpirationTime() {
        byte[] expirationTimeBytes = new byte[4];
        boolean res;
        res = utils.readPages(pageForExpirationTime, 1, expirationTimeBytes, 0);
        if(!res){
            return -1;
        }
        int expirationTime = convertByteArrayToInt(expirationTimeBytes);
        return expirationTime;
    }

    public void writeDefaultAuthenticationKey() throws GeneralSecurityException {
        boolean res = utils.writePages(defaultAuthenticationKey, 0, 44, 4);
        if (!res) {
            Utilities.log("Could not write default auth key", true);
        } else {
            macAlgorithm.setKey(defaultAuthenticationKey);
            Utilities.log("Default auth key written", false);
        }
    }

    public boolean enableAuth0() {
        //enables memory protection on all writable pages starting from page 3
        byte[] authBytes = new byte[]{(byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        boolean success = utils.writePages(authBytes, 0, 0x2A, 1);
        return success;
    }

    public boolean disableAuth0() {
        //disables memory protection
        byte[] authBytes = new byte[]{(byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        boolean success = utils.writePages(authBytes, 0, 0x2A, 1);
        return success;
    }

    public boolean enableReadWriteRestriction() {
        //enables read/write restriction without authentication
        byte[] authBytes = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        boolean success = utils.writePages(authBytes, 0, 0x2B, 1);
        return success;
    }

    public boolean resetCard() throws GeneralSecurityException {
        if (utils.authenticate(defaultAuthenticationKey) || utils.authenticate(calculateDiversifiedAuthKey())) {
            boolean disabled = disableAuth0();
            boolean res = utils.eraseMemory();
            if (!disabled || !res) {
                Utilities.log("Could not reset the card", false);
            }
        } else {
            infoToShow = "Could not authenticate the card";
            Utilities.log(infoToShow, true);
        }
        writeDefaultAuthenticationKey();

        infoToShow = "The card has been reset to the default";
        return true;
    }


}