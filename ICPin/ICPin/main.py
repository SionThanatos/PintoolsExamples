from icpin_importer import Importer

imp = Importer('C:\\Users\\ZAI\\Desktop\\Research\\pin\\PintoolsExamples\\ICPin\\ICPin\\x64\\Debug\\pinatrace.out')
gadgets = imp.loadDB()
print(gadgets)