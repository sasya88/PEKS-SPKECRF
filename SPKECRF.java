import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class SPKECRF {
    private Pairing pairing;
    private Field<Element> G1, G2, Zq;
    private Element P, s, H;
    private Map<String, Element[]> storedCiphertexts = new HashMap<>();
    private Map<String, Element> storedRandomValues = new HashMap<>();

    public SPKECRF() {
        pairing = PairingFactory.getPairing("params/a.properties");
        G1 = pairing.getG1();
        G2 = pairing.getGT();
        Zq = pairing.getZr();

        P = G1.newRandomElement().getImmutable();
        s = Zq.newRandomElement().getImmutable();
        H = P.duplicate().mulZn(s).getImmutable();
    }

    private Element H1(String keyword) {
        byte[] hash = sha256(keyword);
        return G1.newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    private byte[] H2(Element element) {
        return sha256(element.toBytes());
    }

    private byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 error", e);
        }
    }

    private byte[] sha256(String input) {
        return sha256(input.getBytes(StandardCharsets.UTF_8));
    }

    public void encryptKeyword(String keyword, String docID) {
        long startTime = System.nanoTime();

        Element r = Zq.newRandomElement().getImmutable();
        Element H1_W = H1(keyword);
        Element A = P.duplicate().mulZn(r).getImmutable();
        Element t = pairing.pairing(H1_W, H.duplicate().mulZn(r)).getImmutable();
        byte[] B = H2(t);

        Element[] ciphertext = new Element[] { A, pairing.getGT().newElementFromBytes(B).getImmutable() };

        Object[] result = reRandomizePEKS(ciphertext);
        Element[] randomizedCiphertext = (Element[]) result[0];
        Element a = (Element) result[1];

        storedCiphertexts.put(docID, randomizedCiphertext);
        storedRandomValues.put(docID, a);

        long endTime = System.nanoTime();
        System.out.println("Encryption Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
        System.out.println("Encrypted keyword \"" + keyword + "\" for document " + docID);
    }

    public Object[] reRandomizePEKS(Element[] ciphertext) {
        Element a = Zq.newRandomElement().getImmutable();
        Element A_prime = ciphertext[0].duplicate().mulZn(a).getImmutable();
        return new Object[] { new Element[] { A_prime, ciphertext[1] }, a };
    }

    public Element generateTrapdoor(String keyword) {
        return H1(keyword).duplicate().mulZn(s).getImmutable();
    }

    public Element reRandomizeTrapdoor(Element TW, Element a) {
        Element b = a.invert().getImmutable();
        return TW.duplicate().mulZn(b).getImmutable();
    }

    public void searchKeyword(String keyword) {
        long startTime = System.nanoTime();

        Element TW = generateTrapdoor(keyword);
        System.out.println("\nSearching for keyword \"" + keyword + "\"...");
        boolean found = false;

        for (Map.Entry<String, Element[]> entry : storedCiphertexts.entrySet()) {
            String docID = entry.getKey();
            Element A = entry.getValue()[0];
            Element B = entry.getValue()[1];

            Element a = storedRandomValues.get(docID);
            Element TW_prime = reRandomizeTrapdoor(TW, a);

            Element pairingResult = pairing.pairing(TW_prime, A).getImmutable();
            byte[] computedB = H2(pairingResult);

            if (B.isEqual(pairing.getGT().newElementFromBytes(computedB))) {
                System.out.println("Document found: " + docID);
                found = true;
            }
        }

        if (!found) {
            System.out.println("No matching document found.");
        }

        long endTime = System.nanoTime();
        System.out.println("Search Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
    }

    public void keywordGuessingAttack(String[] guessedKeywords) {
        long startTime = System.nanoTime();

        System.out.println("\nPerforming Keyword Guessing Attack...");
        boolean attackSuccess = false;

        for (String guessedKeyword : guessedKeywords) {
            Element guessedTrapdoor = generateTrapdoor(guessedKeyword);

            for (Map.Entry<String, Element[]> entry : storedCiphertexts.entrySet()) {
                Element A = entry.getValue()[0];
                Element B = entry.getValue()[1];
                Element a = Zq.newRandomElement().getImmutable();
                Element TW_prime = reRandomizeTrapdoor(guessedTrapdoor, a);

                Element pairingResult = pairing.pairing(TW_prime, A).getImmutable();
                byte[] computedB = H2(pairingResult);

                if (B.isEqual(pairing.getGT().newElementFromBytes(computedB))) {
                    System.out.println(
                            "Attack Succeeded: Guessed keyword \"" + guessedKeyword + "\" matches stored ciphertext.");
                    attackSuccess = true;
                    break;
                }
            }

            if (attackSuccess)
                break;
        }

        if (!attackSuccess) {
            System.out.println("Attack Failed: Guessed keywords do not match any stored ciphertext.");
        }

        long endTime = System.nanoTime();
        System.out.println("Attack Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
    }

    public static void main(String[] args) {
        SPKECRF spke = new SPKECRF();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Encrypt keyword");
            System.out.println("2. Search keyword");
            System.out.println("3. Perform KGA");
            System.out.println("4. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    System.out.print("Enter keyword: ");
                    String keyword = scanner.nextLine();
                    System.out.print("Enter document ID: ");
                    String docID = scanner.nextLine();
                    spke.encryptKeyword(keyword, docID);
                    break;
                case 2:
                    System.out.print("Enter keyword to search: ");
                    String searchKeyword = scanner.nextLine();
                    spke.searchKeyword(searchKeyword);
                    break;
                case 3:
                    System.out.print("Enter guessed keywords (comma-separated): ");
                    String[] guessedKeywords = scanner.nextLine().split(",");
                    spke.keywordGuessingAttack(guessedKeywords);
                    break;
                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }
}
