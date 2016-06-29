package edu.utexas.utopia;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.xml.stream.XMLStreamException;

import org.xmlpull.v1.XmlPullParserException;

import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration.CallbackAnalyzer;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.source.AndroidSourceSinkManager.LayoutMatchingMode;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory.PathBuilder;
import soot.jimple.infoflow.handlers.ResultsAvailableHandler;
import soot.jimple.infoflow.ipc.IIPCManager;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.results.xml.InfoflowResultsSerializer;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.options.Options;
import soot.util.queue.QueueReader;

public class CryptoLint {
	
	private static InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
	
	private static boolean DEBUG = false;

	/**
	 * @param args Program arguments. args[0] = path to apk-file,
	 * args[1] = path to android-dir (path/android-platforms/)
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
//		args = new String[2];
//		args[0] = "/home/yu/research/benchmarks/malware/drebin-paper/FakeInstaller/88faf677ea6f499065be85156eab6b6fb4d9c6b2c091b5b02d112184523f604f.apk";
//		args[1] = "/home/yu/libs/android-sdk-linux/platforms/";
		if (args.length < 2) {
			System.out.println("Wrong parameters.");
			return;
		}
		//start with cleanup:
		File outputDir = new File("JimpleOutput");
		if (outputDir.isDirectory()){
			boolean success = true;
			for(File f : outputDir.listFiles()){
				success = success && f.delete();
			}
			if(!success){
				System.err.println("Cleanup of output directory "+ outputDir + " failed!");
			}
			outputDir.delete();
		}

		
		List<String> apkFiles = new ArrayList<String>();
		File apkFile = new File(args[0]);
		if (apkFile.isDirectory()) {
			String[] dirFiles = apkFile.list(new FilenameFilter() {
			
				@Override
				public boolean accept(File dir, String name) {
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
			}
			else if (extension.equalsIgnoreCase(".apk"))
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
			}
			else
				fullFilePath = fileName;

			// Run the analysis
					runAnalysis(fullFilePath, args[1]);
			
			System.gc();
		}
	}

	private static InfoflowResults runAnalysis(final String fileName, final String androidJar) {

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
			
			checkCrypto(fileName);
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
	 * @param appPath The application path containing the analysis client
	 * @param libPath The Soot classpath containing the libraries
	 * @param classes The set of classes that shall be checked for data flow
	 * analysis seeds. All sources in these classes are used as seeds. If a
	 * non-empty extra seed is given, this one is used too.
	 */
	
	private static void checkCrypto(String fileName) {
		QueueReader<MethodOrMethodContext> qr = Scene.v().getReachableMethods().listener();
		while(qr.hasNext()) {
			SootMethod meth = (SootMethod) qr.next();
			if(!meth.isJavaLibraryMethod() && meth.hasActiveBody()) {
				String body = meth.getActiveBody().toString();
				if(body.contains("javax.crypto")) {
					System.out.println("Suspicious crypto app: " + fileName);
					System.out.println("crypto body:----------------" + meth.getActiveBody());
				}
				
				if(body.contains("javax.net.ssl")) {
					System.out.println("Suspicious ssl app: " + fileName);
					System.out.println("ssl body:----------------" + meth.getActiveBody());
				}
			}
		}
		
	}
	
}