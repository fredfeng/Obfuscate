package edu.utexas.utopia;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.*;


import org.xmlpull.v1.XmlPullParserException;

import soot.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.toolkits.infoflow.InfoFlowAnalysis;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.HashMutableDirectedGraph;
import soot.toolkits.graph.pdg.HashMutablePDG;
import soot.util.queue.QueueReader;

public class Main
{

    private static InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();

    private static boolean DEBUG = false;

    private static String apkLoc = "";

    /**
     * @param args Program arguments. args[0] = path to apk-file,
     *             args[1] = path to android-dir (path/android-platforms/)
     */
    public static void main(String[] args) throws IOException
    {
//        args = new String[2];
//        args[0] = "/Users/yufeng/research/other/thresher/apps/pldi13/StandupTimer/bin/standup-timer.apk";
//        args[1] = "/Users/yufeng/Library/Android/sdk/platforms/";
        if (args.length < 2) {
            System.out.println("Wrong parameters.");
            return;
        }
        //start with cleanup:
        File outputDir = new File("JimpleOutput");
        if (outputDir.isDirectory()) {
            boolean success = true;
            for (File f : outputDir.listFiles()) {
                success = success && f.delete();
            }
            if (!success) {
                System.err.println("Cleanup of output directory " + outputDir + " failed!");
            }
            outputDir.delete();
        }


        List<String> apkFiles = new ArrayList<String>();
        File apkFile = new File(args[0]);
        apkLoc = apkFile.getName();
        if (apkFile.isDirectory()) {
            String[] dirFiles = apkFile.list(new FilenameFilter()
            {

                @Override
                public boolean accept(File dir, String name)
                {
                    return (name.endsWith(".apk"));
                }

            });
            for (String s : dirFiles)
                apkFiles.add(s);
        } else {
            //apk is a file so grab the extension
            String extension = apkFile.getName().substring(apkFile.getName().lastIndexOf("."));
            if (extension.equalsIgnoreCase(".txt")) {
                BufferedReader rdr = new BufferedReader(new FileReader(apkFile));
                String line = null;
                while ((line = rdr.readLine()) != null)
                    apkFiles.add(line);
                rdr.close();
            } else if (extension.equalsIgnoreCase(".apk"))
                apkFiles.add(args[0]);
            else {
                System.err.println("Invalid input file format: " + extension);
                return;
            }
        }

        for (final String fileName : apkFiles) {
            final String fullFilePath;
            System.gc();

            // Directory handling
            if (apkFiles.size() > 1) {
                if (apkFile.isDirectory())
                    fullFilePath = args[0] + File.separator + fileName;
                else
                    fullFilePath = fileName;
                System.out.println("Analyzing file " + fullFilePath + "...");
                File flagFile = new File("_Run_" + new File(fileName).getName());
                if (flagFile.exists())
                    continue;
                flagFile.createNewFile();
            } else
                fullFilePath = fileName;

            // Run the analysis
            runAnalysis(fullFilePath, args[1]);

            System.gc();
        }
    }

    private static InfoflowResults runAnalysis(final String fileName, final String androidJar)
    {

        try {
            final long beforeRun = System.nanoTime();

            final MySetupApplication app = new MySetupApplication(androidJar, fileName);
            // Set configuration object
            app.setConfig(config);

            app.calculateSourcesSinksEntrypoints("SourcesAndSinks.txt");

            if (DEBUG) {
                app.printEntrypoints();
            }

            System.out.println("Running data flow analysis...");
            final InfoflowResults res = app.runInfoflow(null);
            System.out.println("Analysis has run for " + (System.nanoTime() - beforeRun) / 1E9 + " seconds");

            checkObfuscate();
            return res;
        } catch (IOException ex) {
            System.err.println("Could not read file: " + ex.getMessage());
            ex.printStackTrace();
            throw new RuntimeException(ex);
        } catch (XmlPullParserException ex) {
            System.err.println("Could not read Android manifest file: " + ex.getMessage());
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }

    /**
     * Initializes Soot.
     *
     * @param appPath The application path containing the analysis client
     * @param libPath The Soot classpath containing the libraries
     * @param classes The set of classes that shall be checked for data flow
     *                analysis seeds. All sources in these classes are used as seeds. If a
     *                non-empty extra seed is given, this one is used too.
     */

    private static void checkObfuscate()
    {
        String[] data = {
                "onCreate:onStart",
                "onStart:onResume",
                "onResume:onPause",
                "onPause:onStop:onCreate:onResume",
                "onStop:onDestroy:onRestart:onCreate",
                "onRestart:onStart"
        };
        String[] cycleData = {"onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy", "onRestart"};

        // create graph
        Graph graph = new Graph(Arrays.asList(data), ":");
//        System.out.println(graph);
        String[] goodPattern = {
                "onCreate,onDestroy",
                "onStart,onDestroy",
                "onResume,onStop",
                "onResume,onRestart",
                "onRestart,onDestroy"
        };

        for (SootClass sc : Scene.v().getApplicationClasses()) {
            if (getRoot(sc).getName().equals("android.app.Activity")) {
                Set<String> srcSet = new HashSet<>();
                Set<String> tgtSet = new HashSet<>();
                for (SootMethod m : sc.getMethods()) {
                    if (m.hasActiveBody() && Arrays.asList(cycleData).contains(m.getName())) {
                        Body body = m.getActiveBody();
                        for (Unit u : body.getUnits()) {
                            Stmt stmt = (Stmt) u;
                            if (stmt.containsInvokeExpr()) {
                                SootMethod callee = stmt.getInvokeExpr().getMethod();
//                                if (hasKey(callee.getName())) {
//                                    System.out.println(sc + "-->" + m.getName() + "-->" + callee.getName());
//                                }
                                if (hasAddKey(callee.getName()))
                                    srcSet.add(m.getName());
                                if (hasRemoveKey(callee.getName()))
                                    tgtSet.add(m.getName());
                            }
                        }
                    }
                }
                if (!srcSet.isEmpty() && !tgtSet.isEmpty()) {
//                    System.out.println("*****Activity: " + sc);
//                    System.out.println("src: " + srcSet);
//                    System.out.println("tgt: " + tgtSet);
                    for (String s : srcSet) {
                        for (String t : tgtSet) {
                            String v = s + "," + t;
                            if (Arrays.asList(goodPattern).contains(v)) {
                                System.out.println("%%%%We find a good benchmark in " + sc + "@pattern: " + v + " apkFile: " + apkLoc);
                            }
                        }
                    }
                }

            }
        }

    }

    private static boolean hasKey(String methodName)
    {
        String[] keys = {"add", "remove", "register", "unregister"};
        for (String k : Arrays.asList(keys)) {
            if (methodName.startsWith(k) && (methodName.length() > k.length()))
                return true;
        }

        return false;
    }

    private static boolean hasAddKey(String methodName)
    {
        String[] keys = {"add", "register"};
        for (String k : Arrays.asList(keys)) {
            if (methodName.startsWith(k) && (methodName.length() > k.length()))
                return true;
        }

        return false;
    }

    private static boolean hasRemoveKey(String methodName)
    {
        String[] keys = {"remove", "unregister"};
        for (String k : Arrays.asList(keys)) {
            if (methodName.startsWith(k) && (methodName.length() > k.length()))
                return true;
        }

        return false;
    }

    private static SootClass getRoot(SootClass child)
    {
        if (child.getName().equals("android.app.Activity"))
            return child;

        if (child.hasSuperclass() && !child.getSuperclass().getName().equals("java.lang.Object"))
            return getRoot(child.getSuperclass());
        else
            return child;
    }

}
