// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class VirtualCircuitPublicPrefix {
    /**
     * @return (Updatable) An individual public IP prefix (CIDR) to add to the public virtual circuit. All prefix sizes are allowed.
     * 
     */
    private final String cidrBlock;

    @CustomType.Constructor
    private VirtualCircuitPublicPrefix(@CustomType.Parameter("cidrBlock") String cidrBlock) {
        this.cidrBlock = cidrBlock;
    }

    /**
     * @return (Updatable) An individual public IP prefix (CIDR) to add to the public virtual circuit. All prefix sizes are allowed.
     * 
     */
    public String cidrBlock() {
        return this.cidrBlock;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VirtualCircuitPublicPrefix defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String cidrBlock;

        public Builder() {
    	      // Empty
        }

        public Builder(VirtualCircuitPublicPrefix defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cidrBlock = defaults.cidrBlock;
        }

        public Builder cidrBlock(String cidrBlock) {
            this.cidrBlock = Objects.requireNonNull(cidrBlock);
            return this;
        }        public VirtualCircuitPublicPrefix build() {
            return new VirtualCircuitPublicPrefix(cidrBlock);
        }
    }
}
