# Documentation

UML_FILES = \
	phy_state_machine.uml

docs: $(patsubst %.uml, %.svg, $(UML_FILES))

.SUFFIXES: .uml .svg

.uml.svg:
	plantuml -tsvg $<
	dos2unix $@
