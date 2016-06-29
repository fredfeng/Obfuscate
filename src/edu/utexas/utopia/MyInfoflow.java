package edu.utexas.utopia;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import soot.Scene;
import soot.jimple.infoflow.AbstractInfoflow;
import soot.jimple.infoflow.cfg.BiDirICFGFactory;
import soot.jimple.infoflow.data.pathBuilders.IPathBuilderFactory;
import soot.jimple.infoflow.entryPointCreators.IEntryPointCreator;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.source.ISourceSinkManager;

public class MyInfoflow extends AbstractInfoflow{
	
	public MyInfoflow(String androidPath, boolean forceAndroidJar, BiDirICFGFactory icfgFactory,
			IPathBuilderFactory pathBuilderFactory) {
		super(icfgFactory, androidPath, forceAndroidJar);
	}
	
	@Override
	public void computeInfoflow(String appPath, String libPath, String entryPoint, ISourceSinkManager sourcesSinks) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public InfoflowResults getResults() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isResultAvailable() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void computeInfoflow(String appPath, String libPath, IEntryPointCreator entryPointCreator,
			ISourceSinkManager sourcesSinks) {
		// TODO Auto-generated method stub
		initializeSoot(appPath, libPath, entryPointCreator.getRequiredClasses());
		Scene.v().setEntryPoints(Collections.singletonList(entryPointCreator.createDummyMain()));
		constructCallgraph();
	}

}
