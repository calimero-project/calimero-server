import org.gradle.kotlin.dsl.runtimeClasspath
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.jar.JarFile
import kotlin.collections.flatMap
import kotlin.collections.plus

plugins {
	`java-library`
	application
	`maven-publish`
	signing
	id("org.graalvm.buildtools.native") version "1.1.0"
	id("com.github.ben-manes.versions") version "0.54.0"
}

repositories {
	mavenCentral()
	mavenLocal()
	maven("https://central.sonatype.com/repository/maven-snapshots/")
}

val junitJupiterVersion by rootProject.extra { "6.0.0" }

group = "io.calimero"
version = "3.0-SNAPSHOT"

sourceSets {
	main {
		java.srcDir("src")
		resources.srcDir("resources")
	}
	test {
		java.srcDirs("test")
		file("build/classes/test").mkdirs()
		runtimeClasspath += files("build/classes/test")
	}

	create("serial")
	create("usb")
}

java {
	toolchain {
		languageVersion.set(JavaLanguageVersion.of(21))
	}
	withSourcesJar()
	withJavadocJar()

	registerFeature("serial") {
		usingSourceSet(sourceSets["serial"])
	}
	registerFeature("usb") {
		usingSourceSet(sourceSets["usb"])
	}
}

// we don't need the serial/usb feature jars when publishing
tasks.named("serialJar") { enabled = false }
tasks.named("usbJar") { enabled = false }

tasks.withType<Jar>().configureEach {
	from(projectDir) {
		include("LICENSE.txt")
		into("META-INF")
	}
	if (name == "sourcesJar") {
		from(projectDir) {
			include("README.md")
		}
	}
}

tasks.withType<JavaCompile>().configureEach {
	options.encoding = "UTF-8"
}

tasks.withType<Javadoc>().configureEach {
	options.encoding = "UTF-8"
}

application {
	mainModule.set("io.calimero.server")
	mainClass.set("io.calimero.server.Launcher")
}

tasks.named<JavaExec>("run") {
	standardInput = System.`in`
}

tasks.withType<JavaCompile>().configureEach {
	options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-auxiliaryclass"))
}

tasks.named<JavaCompile>("compileJava") {
	options.javaModuleVersion = project.version.toString()
}

tasks.withType<Javadoc>().configureEach {
	(options as CoreJavadocOptions).addStringOption("Xdoclint:-missing", "-quiet")
}

testing {
	suites {
		val test by getting(JvmTestSuite::class) {
			useJUnitJupiter("${rootProject.extra.get("junitJupiterVersion")}")
		}
	}
}

// note, task 'package' --add-reads options need to be kept in sync with this
val addReads = listOf(
	"--add-reads", "io.calimero.core=io.calimero.server", // @LinkEvent
	"--add-reads", "io.calimero.serial.provider.rxtx=ALL-UNNAMED",
	"--add-reads", "io.calimero.usb.provider.javax=ALL-UNNAMED" // javax.usb:usb-api
)

val enableNativeAccess = listOf(
	"--enable-native-access=io.calimero.serial.provider.jni,serial.ffm,org.usb4java",
	"--enable-native-access=ALL-UNNAMED", // libs used by rxtx
)

tasks.withType<JavaExec>().configureEach {
	jvmArgs(addReads)
	jvmArgs(enableNativeAccess)
}

tasks.named<CreateStartScripts>("startScripts") {
	defaultJvmOpts = addReads + enableNativeAccess
}

dependencies {
	api("io.calimero:calimero-core:$version")
	api("io.calimero:calimero-device:$version")

	add("serialRuntimeOnly", "io.calimero:calimero-rxtx:$version")
	add("serialRuntimeOnly", "io.calimero:serial-native:$version")
	if (java.toolchain.languageVersion.get() >= JavaLanguageVersion.of(23))
		add("serialRuntimeOnly", "io.calimero:calimero-serial-ffm:$version")
	add("usbRuntimeOnly", "io.calimero:calimero-usb:$version")
	runtimeOnly(sourceSets["serial"].runtimeClasspath)
	runtimeOnly(sourceSets["usb"].runtimeClasspath)

	runtimeOnly("org.slf4j:slf4j-jdk-platform-logging:2.0.17")
	runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
}

tasks.named<Jar>("jar") {
	manifest {
		val gitHash = providers.exec {
			commandLine("git", "-C", "$projectDir", "rev-parse", "--verify", "--short", "HEAD")
		}.standardOutput.asText.map { it.trim() }
		val buildDate = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
			.withZone(ZoneId.of("UTC"))
			.format(Instant.now())

		attributes(
			"Main-Class" to application.mainClass.get(),
			"Implementation-Version" to project.version,
			"Revision" to gitHash.get(),
			"Build-Date" to buildDate,
			"Class-Path" to configurations.runtimeClasspath.get().files.joinToString(" ") { it.name }
		)
	}

	exclude("server-config.xml")
}

tasks.named<JavaExec>("run") {
	// Work around https://github.com/graalvm/native-build-tools/issues/743
	outputs.upToDateWhen { false }
}

// graalvm native image uses jdk 25, so we can include serial-ffm which requires java 23
val nativeImageSerialFfm by configurations.creating
dependencies {
	nativeImageSerialFfm("io.calimero:calimero-serial-ffm:$version")
}

graalvmNative {
//	toolchainDetection = true // only works reliably if a single JDK is installed, which is GraalVM
	agent {
//		enabled = true
		defaultMode = "standard"
	}
	binaries {
		named("main") {
//			verbose = true
			sharedLibrary = false
			mainClass.set(project.name) // yes, this sets the output name for some reason

			val modulePathJars = (classpath.files + nativeImageSerialFfm.files).filter { file ->
				file.exists() && file.name.endsWith(".jar") &&
						JarFile(file, true, JarFile.OPEN_READ, Runtime.version()).use { jar ->
							jar.getEntry("module-info.class") != null ||
							jar.manifest?.mainAttributes?.getValue("Automatic-Module-Name") != null ||
							jar.versionedStream().anyMatch { entry -> entry.name.endsWith("/module-info.class") }
						}
			}

			buildArgs.addAll(
				listOf(
					"--module-path", modulePathJars.joinToString(File.pathSeparator),
					"--module", "io.calimero.server/io.calimero.server.Launcher",
//					"--future-defaults=all",
					"--initialize-at-build-time",
					"-march=native",
					"-Os",
					"--no-fallback",
					"--exact-reachability-metadata",
					"-H:-ReportExceptionStackTraces",
					"-H:+UnlockExperimentalVMOptions",
					"-H:-EnableLoggingFeature",
				)
			)
			buildArgs.addAll(addReads)
			buildArgs.addAll(enableNativeAccess)

			val oracleGraalVm = System.getProperty("java.vm.vendor").contains("Oracle", true)
					&& !System.getProperty("java.vm.name").contains("OpenJDK", true)
			if (oracleGraalVm)
				buildArgs.addAll("--enable-sbom=export", "--emit build-report")
		}
	}
}

val appName = project.name
val packageDir = layout.buildDirectory.dir("package")
val runtimeDir = packageDir.map { it.dir("runtime") }
val appDir = packageDir.map { it.dir("app") }
val jarTask = tasks.named<Jar>("jar")

val os = org.gradle.internal.os.OperatingSystem.current()!!
val arch = System.getProperty("os.arch")!!

abstract class JdepsTask : DefaultTask() {
	@get:Input
	abstract val version: Property<String>
	@get:InputFiles
	abstract val modules: ConfigurableFileCollection
	@get:OutputFile
	abstract val outputFile: RegularFileProperty
	@get:Inject
	abstract val execOperations: ExecOperations

	@TaskAction
	fun jdeps() {
		val result = ByteArrayOutputStream()
		execOperations.exec {
			val jdeps = listOf("jdeps",
				"--print-module-deps", "--ignore-missing-deps", "--multi-release", version.get(),
				"--recursive", "-quiet", "--module-path", modules.asPath
			) + modules.files.map { it.path }
			commandLine(jdeps)
			standardOutput = result
		}
		outputFile.get().asFile.writeText(result.toString().trim())
	}
}

val jdepsTask = tasks.register<JdepsTask>("jdeps") {
	group = "other"
	description = "Finds the module dependencies for the main binary"
	dependsOn("jar")

	version.set(java.toolchain.languageVersion.map { it.toString() })
	modules.from(configurations.runtimeClasspath.get().filter { it.exists() }, jarTask)
	outputFile.set(packageDir.get().file("jdeps.out"))
}

tasks.register<Delete>("cleanRuntime") {
	delete(runtimeDir)
}

tasks.register<Exec>("runtime") {
	group = "build"
	description = "Creates a Java runtime for the main binary"
	dependsOn("cleanRuntime")
	val jdepsOutput = jdepsTask.flatMap { it.outputFile }
	inputs.file(jdepsOutput)

	val output = runtimeDir.get().asFile.path
	doFirst {
		val jdkModules = jdepsOutput.get().asFile.readText().replace(",java.xml", "")
		val jlink = listOf("jlink",
			"--no-header-files", "--no-man-pages", "--strip-debug", "--strip-native-commands",
			"--compress", "zip-9",
			"--output", output,
			"--add-modules", jdkModules,
			"--limit-modules", jdkModules,
		)
		commandLine(jlink)
	}
}

tasks.register<Copy>("preparePackageJars") {
	dependsOn("jar")
	from(configurations.runtimeClasspath, jarTask)
	into(packageDir.get().dir("libs"))
	exclude(
		when {
			os.isLinux   -> listOf("darwin", "win")
			os.isMacOsX  -> listOf("linux", "win")
			os.isWindows -> listOf("darwin", "linux")
			else         -> error("unsupported OS $os")
		}.map { "libusb4java-*-$it*.jar" }
	)
	exclude(
		when (arch) {
			"aarch64"         -> listOf("x86*", "arm*")
			"amd64", "x86_64" -> listOf("aarch64*", "arm*", "x86") // no asterisk on x86 to not match x86_64
			else              -> listOf("aarch64*", "arm*", "x86_64*")
		}.map { "libusb4java-*$it.jar" }
	)
}

tasks.register<Copy>("copySerialNativeLib") {
	val serialNativeDir = file("../serial-native/bin/")
	from(serialNativeDir) {
		val libArch = if (arch == "aarch64") "aarch64" else "x86_64"
		include(when {
			os.isLinux   -> "linux-$libArch/libserialcom.so"
			os.isMacOsX  -> "darwin-$libArch/libserialcom.dylib"
			os.isWindows -> "win-$libArch/serialcom.dll"
			else         -> error("unsupported OS $os")
		})
		eachFile { path = name }
		includeEmptyDirs = false
	}
	into(packageDir.get().dir(
		when {
			os.isMacOsX -> "native/Frameworks"
			else        -> "native"
		})
	)
}

tasks.register<Delete>("cleanPackageApp") {
	delete(appDir)
}

tasks.register<Exec>("package") {
	group = "build"
	description = "Packages a self-contained Java application for the main binary"
	dependsOn("runtime", "cleanPackageApp", "preparePackageJars", "copySerialNativeLib")
	finalizedBy(if (os.isWindows) "zipAppImage" else "tarAppImage") // for Linux/Win, where jpackage creates an app folder

	val baseArgs = listOf("jpackage",
		"--type", "app-image",
		"--name", appName,
		"--description", "KNX/IP server",
		"--runtime-image", runtimeDir.get().asFile.path,
		"--module", application.mainModule.get(),
		"--module-path", packageDir.get().dir("libs").asFile.absolutePath,
		"--app-version", version.toString().substringBefore("-"),
		"--dest", appDir.get().asFile,
	)

	val javaOptionArgs = (
			enableNativeAccess +
					listOf(
						"--enable-native-access=nrjavaserial",
						"--add-reads=io.calimero.core=io.calimero.server", // @LinkEvent
						"--add-reads=io.calimero.serial.provider.rxtx=nrjavaserial",
						"--add-reads=io.calimero.usb.provider.javax=usb.api"
					)
			).flatMap { listOf("--java-options", it) }

	val nativeDir = provider { packageDir.get().dir("native") }
	val os = os
	doFirst {
		val nativeArgs =
			if (!nativeDir.get().asFile.exists()) emptyList()
			else {
				val libDir = if (os.isMacOsX) "Frameworks" else "."
				val libPath = if (os.isMacOsX) "\$APPDIR/../Frameworks" else "\$APPDIR/../native"
				listOf(
					"--app-content", nativeDir.get().dir(libDir).asFile.path,
					"--java-options", "-Djava.library.path=$libPath"
				)
			}

		commandLine(baseArgs + javaOptionArgs + nativeArgs)
	}
}

tasks.register<Zip>("zipAppImage") {
	dependsOn("package")
	from(appDir.get().dir(appName))
	archiveFileName.set("$appName.zip")
	destinationDirectory.set(file(appDir))
}

tasks.register<Tar>("tarAppImage") {
	dependsOn("package")
	from(appDir.get().dir(appName)) {
		filesMatching("**/$appName") { // preserve executable bit
			permissions { unix("rwxr-xr-x") }
		}
	}
	archiveFileName.set("$appName.tar.gz")
	destinationDirectory.set(appDir)
	compression = Compression.GZIP
}

publishing {
	publications {
		create<MavenPublication>("mavenJava") {
			artifactId = rootProject.name
			from(components["java"])
			pom {
				name.set("Calimero KNXnet/IP Server")
				description.set("Calimero KNXnet/IP server is a free KNX network server")
				url.set("https://github.com/calimero-project/calimero-server")
				inceptionYear.set("2006")
				licenses {
					license {
						name.set("GNU General Public License, version 2, with the Classpath Exception")
						url.set("LICENSE.txt")
					}
				}
				developers {
					developer {
						name.set("Boris Malinowsky")
						email.set("b.malinowsky@gmail.com")
					}
				}
				scm {
					connection.set("scm:git:git://github.com/calimero-project/calimero-server.git")
					url.set("https://github.com/calimero-project/calimero-server.git")
				}
			}
		}
	}
	repositories {
		maven {
			name = "maven"
			val releasesRepoUrl = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
			val snapshotsRepoUrl = uri("https://central.sonatype.com/repository/maven-snapshots/")
			url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
			credentials(PasswordCredentials::class)
		}
	}
}

signing {
	if (project.hasProperty("signing.keyId")) {
		sign(publishing.publications["mavenJava"])
	}
}
