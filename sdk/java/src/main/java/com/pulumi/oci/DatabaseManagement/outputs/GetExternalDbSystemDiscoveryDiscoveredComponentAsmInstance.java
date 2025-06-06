// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance {
    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    private String adrHomeDirectory;
    /**
     * @return The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    private String hostName;
    /**
     * @return The name of the ASM instance.
     * 
     */
    private String instanceName;

    private GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance() {}
    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    public String adrHomeDirectory() {
        return this.adrHomeDirectory;
    }
    /**
     * @return The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return The name of the ASM instance.
     * 
     */
    public String instanceName() {
        return this.instanceName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adrHomeDirectory;
        private String hostName;
        private String instanceName;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adrHomeDirectory = defaults.adrHomeDirectory;
    	      this.hostName = defaults.hostName;
    	      this.instanceName = defaults.instanceName;
        }

        @CustomType.Setter
        public Builder adrHomeDirectory(String adrHomeDirectory) {
            if (adrHomeDirectory == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance", "adrHomeDirectory");
            }
            this.adrHomeDirectory = adrHomeDirectory;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder instanceName(String instanceName) {
            if (instanceName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance", "instanceName");
            }
            this.instanceName = instanceName;
            return this;
        }
        public GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance build() {
            final var _resultValue = new GetExternalDbSystemDiscoveryDiscoveredComponentAsmInstance();
            _resultValue.adrHomeDirectory = adrHomeDirectory;
            _resultValue.hostName = hostName;
            _resultValue.instanceName = instanceName;
            return _resultValue;
        }
    }
}
