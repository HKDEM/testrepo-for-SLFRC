// VULNERABLE: public REST endpoint, no session/auth enforcement, returns sensitive fields
@RestResource(urlMapping='/insecure/*')
global with sharing class InsecureSecurityTest {

    // VULNERABLE: uses dynamic SOQL with direct string concatenation -> SOQL injection
    @HttpGet
    global static String getAccounts() {
        RestRequest req = RestContext.request;
        String nameParam = req.requestURI.substring(req.requestURI.lastIndexOf('/')+1);
        // SOQL injection: nameParam is concatenated directly
        String q = 'SELECT Id, Name, Phone, OwnerId FROM Account WHERE Name LIKE \'%' + nameParam + '%\'';
        List<Account> accs = Database.query(q);

        // VULNERABLE: hard-coded API key/credentials in source
        String apiKey = 'hardcoded-api-key-DO-NOT-USE';
        System.debug('APIKEY: ' + apiKey);

        // VULNERABLE: weak hashing for passwords (MD5) - not suitable for secrets
        Blob pwBlob = Blob.valueOf('password123');
        Blob md5 = Crypto.generateDigest('MD5', pwBlob);
        String md5Hex = EncodingUtil.convertToHex(md5);

        // VULNERABLE: DML inside loop later (demonstration) - bad for performance and bulk
        for (Account a : accs) {
            Contact c = new Contact(LastName = 'Auto', AccountId = a.Id);
            insert c; // DML inside loop
        }

        return JSON.serializePretty(new Map<String,Object>{
            'accounts' => accs,
            'md5' => md5Hex
        });
    }

    // VULNERABLE: @AuraEnabled method exposed without CRUD/FLS checks or sharing enforcement
    @AuraEnabled
    public static List<Contact> getContactsForAccount(String acctId) {
        // no with sharing enforcement, no check for read access
        return [SELECT Id, LastName, Email FROM Contact WHERE AccountId = :acctId];
    }
}
