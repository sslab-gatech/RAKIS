PREFIX=$(HOME)/.local

all:
	@echo "[!] This Makefile is only for use by Eurosys'25 AE reviewers."
	@echo "    Please use the instructions in README.md otherwise."

define build
		meson setup $(1)/ --buildtype=release $(2) --prefix=$(3)
		ninja -C $(1)/ install
		ln -sf $(1)/compile_commands.json compile_commands.json
endef

eurosys-reproduce:
	@echo "[*] Building Vanilla Gramine...\n"
	git checkout gramine-v1.5
	@$(call build,build-release-vanilla-gramine,-Ddirect=enabled -Dskeleton=disabled -Dsgx=enabled,$(PREFIX)/gramine)
	git checkout master
	@echo "[*] Vanilla Gramine built successfully.\n"

	@echo "[*] Building RAKIS Gramine...\n"
	@$(call build,build-release-rakis-gramine,-Ddirect=enabled -Dskeleton=disabled -Dsgx=enabled -Drakis=enabled -Dinstall_with_caps=enabled,$(PREFIX)/rakis)
	@echo "[*] RAKIS Gramine built successfully.\n\n"

	@echo "********************************************************************************"
	@echo "* You are now ready to produce our paper results.                              *"
	@echo "* In short, for every workload we used in our paper, you can find a folder     *"
	@echo "* with the workload name inside 'CI-Examples/'. Within each workload folder,   *"
	@echo "* read the README.md file within and then you can run                          *"
	@echo "* 'make eurosys-reproduce'. At the end of each experiment we will present you  *"
	@echo "* with instructions and steps to go to the next part of results reproduction.  *"
	@echo "*                                                                              *"
	@echo "* Please continue to CI-Examples/iperf3 to run the first experiment.           *"
	@echo "********************************************************************************"
