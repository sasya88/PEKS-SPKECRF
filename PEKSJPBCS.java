import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PEKSJPBCS {
    private Pairing pairing;
    private Field<Element> G1, G2, Zq;
    private Element P, s, H;
    private Map<String, Element[]> storedCiphertexts = new HashMap<>();

    public PEKSJPBCS() {
        pairing = PairingFactory.getPairing("params/a.properties"); // Load JPBC parameters
        G1 = pairing.getG1();
        G2 = pairing.getGT();
        Zq = pairing.getZr();

        P = G1.newRandomElement().getImmutable(); // Generator P
        s = Zq.newRandomElement().getImmutable(); // Secret key s
        H = P.duplicate().mulZn(s).getImmutable(); // Public key H = sP
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

        storedCiphertexts.put(docID, new Element[] { A, pairing.getGT().newElementFromBytes(B).getImmutable() });
        long endTime = System.nanoTime();
        System.out.println("Encrypted \"" + keyword + "\" for Document ID: " + docID);
        System.out.println("Encryption Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
    }

    public Element generateTrapdoor(String keyword) {
        return H1(keyword).duplicate().mulZn(s).getImmutable();
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

            Element pairingResult = pairing.pairing(TW, A).getImmutable();
            byte[] computedB = H2(pairingResult);

            if (B.isEqual(pairing.getGT().newElementFromBytes(computedB))) {
                System.out.println(" Document found: " + docID);
                found = true;
            }
        }

        if (!found) {
            System.out.println(" No matching document found.");
        }
        long endTime = System.nanoTime();
        System.out.println("PEKS Search Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
    }

    public void keywordGuessingAttack(String[] dictionary) {
        long startTime = System.nanoTime();
        System.out.println("\nPerforming Keyword Guessing Attack...");

        for (String guess : dictionary) {
            Element trapdoorGuess = generateTrapdoor(guess);

            for (Map.Entry<String, Element[]> entry : storedCiphertexts.entrySet()) {
                Element A = entry.getValue()[0];
                Element B = entry.getValue()[1];

                Element pairingResult = pairing.pairing(trapdoorGuess, A).getImmutable();
                byte[] computedB = H2(pairingResult);

                if (B.isEqual(pairing.getGT().newElementFromBytes(computedB))) {
                    long endTime = System.nanoTime();
                    System.out.println("Keyword found: " + guess + " (Document ID: " + entry.getKey() + ")");
                    System.out.println("KGA Attack Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
                    return;
                }
            }
        }

        long endTime = System.nanoTime();
        System.out.println("KGA Attack Failed. No matching keyword found.");
        System.out.println("KGA Attack Time: " + (endTime - startTime) / 1_000_000.0 + " ms");
    }

    public static void main(String[] args) {
        PEKSJPBCS peks = new PEKSJPBCS();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Encrypt Keyword");
            System.out.println("2. Search Keyword");
            System.out.println("3. Perform KGA Attack");
            System.out.println("4. Exit");
            System.out.print("Enter choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    System.out.print("Enter keyword: ");
                    String keyword = scanner.nextLine();
                    System.out.print("Enter document ID: ");
                    String docID = scanner.nextLine();
                    peks.encryptKeyword(keyword, docID);
                    break;

                case 2:
                    System.out.print("Enter keyword to search: ");
                    String searchKeyword = scanner.nextLine();
                    peks.searchKeyword(searchKeyword);
                    break;

                case 3:
                    System.out.print("Enter comma-separated dictionary for KGA attack: ");
                    String[] dictionary = scanner.nextLine().split(",");
                    peks.keywordGuessingAttack(dictionary);
                    break;

                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    return;

                default:
                    System.out.println("Invalid choice! Please try again.");
            }
        }
    }
}
