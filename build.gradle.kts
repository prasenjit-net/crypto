/*
 *    Copyright 2023 Prasenjit Purohit
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
plugins {
    `java-library`
    `maven-publish`
    signing
    `project-report`
    alias(libs.plugins.release)
    alias(libs.plugins.publish)
    alias(libs.plugins.versions)
}

//val version: String? by project
//println(version)

description = "A Cryptographic Operation Utility Library"
group = "io.github.prasenjit-net"
//version = version!!

java.sourceCompatibility = JavaVersion.VERSION_1_8

dependencies {
    api(libs.bundles.compile)

    testImplementation(libs.bundles.test)
}

java {
    withJavadocJar()
    withSourcesJar()
}

tasks.jar {
    manifest {
        attributes(
                mapOf(
                        "Implementation-Title" to project.name,
                        "Implementation-Version" to project.version,
                        "Description" to project.description
                )
        )
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

repositories {
    mavenCentral()
}

release {
//    version = cryptoVersion!!
    git {
        requireBranch = "master"
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("Crypto")
                description.set("A easy to use cryptography library implementing common use cases for enterprise security requirements.")
                url.set("https://www.prasenjit.net/crypto/")
                licenses {
                    licenses {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        name.set("Prasenjit Purohit")
                        email.set("prasenjit@prasenjit.net")
                        organization.set("Prasenjit.net")
                        organizationUrl.set("https://www.prasenjit.net")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/prasenjit-net/crypto.git")
                    developerConnection.set("scm:git:https://github.com/prasenjit-net/crypto.git")
                    url.set("https://github.com/prasenjit-net/crypto")
                    tag.set("HEAD")
                }
            }
        }
    }

    repositories {
        maven {
            val repoUsername: String? by project
            val repoPassword: String? by project
            name = "OSSRH"
            val snapshotRepo = "https://oss.sonatype.org/content/repositories/snapshots/"
            val releaseRepo = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotRepo else releaseRepo)
            credentials {
                username = repoUsername
                password = repoPassword
            }
        }
    }
}

signing {
    if (System.getenv("CI") != null) {
        useGpgCmd()
    }
    sign(publishing.publications)
}