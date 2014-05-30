import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JPWGen {
    private static final Logger logger = LoggerFactory.getLogger(JPWGen.class);

    @Parameter(names = {"-wld", "--wordlistdir"}, description = "wordlists come from here")
    File wordListDir = null;
    @Parameter(names = {"-fsf", "--fileSuffixFilter"}, description = "files have to match this name pattern")
    private WildcardFileFilter wildcardFileFilter = new WildcardFileFilter("*.txt");
    @Parameter(names = {"-mr", "--matchregex"}, converter = MatcherConverter.class, description = "by this regex lines are filtered. observe filtered lines by adding debug")
    private Matcher lineMatcher = Pattern.compile("(?i)[a-z]*[aeuioy][a-z]*").matcher("");
    @Parameter(names = {"-mwl", "--minwordlength"}, description = "wordlength must be greater or equal")
    private Integer minWordLength = 3;
    @Parameter(names = {"-w", "--wordcount"}, description = "sets the wordcount for produced password")
    private Integer wordCount = 5;
    @Parameter(names = { "-f", "--fillString" }, description = "String put between words to increase entropy")
    private String fillString = "";
    @Parameter(names = { "-p", "--pwcount" }, description = "this many passwords will be generated")
    private Integer passwordCount = 10;
    @Parameter(names = { "-d", "--debug" }, description = "Debug mode")
    private boolean isDebug = false;
    @Parameter(names = { "-h", "--help" }, description = "prints usage", help = true)
    private boolean isHelp = false;

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        JPWGen jpwGen = new JPWGen();
        JCommander jCommander = new JCommander(jpwGen);
        jCommander.setProgramName(jpwGen.getClass().getSimpleName());

        try {
            jCommander.parse(args);
            if (jpwGen.isHelp()) {
                jCommander.usage();
                return;
            }

            jpwGen.run();
        } catch (ParameterException e) {
            logger.error(e.getMessage());
            jCommander.usage();
        } catch (Exception e) {
            logger.error("error in main", e);
        }
    }

    private void run() throws FileNotFoundException, UnsupportedEncodingException {
        if (this.fillString.isEmpty())
            logger.warn("fillstring is empty. this reduces entropy.");

        Set<String> uniqueLines = new HashSet<String>();
        Set<String> filteredLines = new HashSet<String>();

        searchForWordlistFiles(uniqueLines, filteredLines, getClassLoaderPath());
        if (wordListDir != null && wordListDir.isDirectory())
            searchForWordlistFiles(uniqueLines, filteredLines, wordListDir);

        if (this.isDebug) {
            List<String> filteredList = new ArrayList<String>(filteredLines);

            Collections.sort(filteredList, new Comparator<String>() {
                @Override
                public int compare(String o1, String o2) {
                    return Integer.valueOf(o1.length()).compareTo(o2.length());
                }
            });
            Collections.reverse(filteredList);
            logger.debug("filtered lines (longest lines go first): {}", StringUtils.join(filteredList, ", "));
        }

        if (uniqueLines.isEmpty())
            throw new IllegalArgumentException("no lines to process");

        List<String> allLines = new ArrayList<String>(uniqueLines);
        Collections.sort(allLines);
        for (int i = 0; i < this.passwordCount; i++) {
            generatePassword(allLines);
        }
    }

    private void searchForWordlistFiles(Set<String> uniqueLines, Set<String> filteredLines, File file) {
        logger.info("searching path {} for files matching {}", file.getAbsolutePath(), wildcardFileFilter.toString());
        for (File f : file.listFiles((java.io.FileFilter) wildcardFileFilter)) {
            logger.info("found file {}", f.getName());
            processFile(uniqueLines, filteredLines, f);
        }
    }

    private File getClassLoaderPath() throws UnsupportedEncodingException {
        String path = this.getClass().getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = URLDecoder.decode(path, "UTF-8");
        return new File(decodedPath).getParentFile();
    }

    private void generatePassword(List<String> allLines) {
        Set<String> chosenLines = new LinkedHashSet<String>();
        while (this.wordCount > chosenLines.size()) {
            int i = getRandomInstance().nextInt(allLines.size());
            String s = allLines.get(i);
            if (this.isDebug)
                logger.debug("{} => {}", i, s);
            chosenLines.add(s);
        }
        logger.info("[ {} ] [ {} ] length {}, entropy {}", StringUtils.join(chosenLines, " "), StringUtils.join(chosenLines, this.fillString),
                getLength(chosenLines), calcEntropy(allLines.size(), chosenLines.size()));
    }

    private int getLength(Collection<String> collection) {
        int length = 0;
        for (String s : collection) {
            length += s.length();
        }
        return length;
    }

    private Random getRandomInstance() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.nextBytes(new byte[512]); // Calling nextBytes method to generate Random Bytes
            return random;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("was unable to instanciate PRNG", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("was unable to instanciate PRNG", e);
        }
    }

    private void processFile(Set<String> uniqueLines, Set<String> filteredLines, File file) {
        if (file == null || uniqueLines == null)
            return;
        try {
            List<String> allLinesFromFile = FileUtils.readLines(file, "UTF-8");
            for (String line : allLinesFromFile) {
                if (linePassesFilter(line))
                    uniqueLines.add(line.toLowerCase());
                else
                    filteredLines.add(line.toLowerCase());
            }
        } catch (IOException e) {
            logger.error("error in processFile", e);
        }
    }

    private boolean linePassesFilter(String line) {
        lineMatcher.reset(line);
        return lineMatcher.matches() && line.length() >= minWordLength;
    }

    public boolean isHelp() {
        return isHelp;
    }

    public BigDecimal calcEntropy(int base, int exponent) {
        BigDecimal pow = BigDecimal.valueOf(base).pow(exponent, MathContext.DECIMAL128);
        BigDecimal logValue = BigDecimal.valueOf(Math.log(pow.doubleValue()));
        BigDecimal logTwo = BigDecimal.valueOf(Math.log(2.00));
        return logValue.divide(logTwo, MathContext.DECIMAL128).setScale(2, RoundingMode.DOWN);
    }

    private class MatcherConverter implements IStringConverter<Matcher> {
        @Override
        public Matcher convert(String s) {
            return Pattern.compile(s).matcher("");
        }
    }


    private class WildcardFileFilterConverter implements IStringConverter<WildcardFileFilter> {
        @Override
        public WildcardFileFilter convert(String s) {
            return new WildcardFileFilter(s);
        }
    }


}
