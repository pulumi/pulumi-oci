// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetRecoveryServiceSubnetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRecoveryServiceSubnetPlainArgs Empty = new GetRecoveryServiceSubnetPlainArgs();

    /**
     * The recovery service subnet OCID.
     * 
     */
    @Import(name="recoveryServiceSubnetId", required=true)
    private String recoveryServiceSubnetId;

    /**
     * @return The recovery service subnet OCID.
     * 
     */
    public String recoveryServiceSubnetId() {
        return this.recoveryServiceSubnetId;
    }

    private GetRecoveryServiceSubnetPlainArgs() {}

    private GetRecoveryServiceSubnetPlainArgs(GetRecoveryServiceSubnetPlainArgs $) {
        this.recoveryServiceSubnetId = $.recoveryServiceSubnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRecoveryServiceSubnetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecoveryServiceSubnetPlainArgs $;

        public Builder() {
            $ = new GetRecoveryServiceSubnetPlainArgs();
        }

        public Builder(GetRecoveryServiceSubnetPlainArgs defaults) {
            $ = new GetRecoveryServiceSubnetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param recoveryServiceSubnetId The recovery service subnet OCID.
         * 
         * @return builder
         * 
         */
        public Builder recoveryServiceSubnetId(String recoveryServiceSubnetId) {
            $.recoveryServiceSubnetId = recoveryServiceSubnetId;
            return this;
        }

        public GetRecoveryServiceSubnetPlainArgs build() {
            if ($.recoveryServiceSubnetId == null) {
                throw new MissingRequiredPropertyException("GetRecoveryServiceSubnetPlainArgs", "recoveryServiceSubnetId");
            }
            return $;
        }
    }

}
