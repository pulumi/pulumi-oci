// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetProtectedDatabaseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProtectedDatabaseArgs Empty = new GetProtectedDatabaseArgs();

    /**
     * The protected database OCID.
     * 
     */
    @Import(name="protectedDatabaseId", required=true)
    private Output<String> protectedDatabaseId;

    /**
     * @return The protected database OCID.
     * 
     */
    public Output<String> protectedDatabaseId() {
        return this.protectedDatabaseId;
    }

    private GetProtectedDatabaseArgs() {}

    private GetProtectedDatabaseArgs(GetProtectedDatabaseArgs $) {
        this.protectedDatabaseId = $.protectedDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProtectedDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProtectedDatabaseArgs $;

        public Builder() {
            $ = new GetProtectedDatabaseArgs();
        }

        public Builder(GetProtectedDatabaseArgs defaults) {
            $ = new GetProtectedDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param protectedDatabaseId The protected database OCID.
         * 
         * @return builder
         * 
         */
        public Builder protectedDatabaseId(Output<String> protectedDatabaseId) {
            $.protectedDatabaseId = protectedDatabaseId;
            return this;
        }

        /**
         * @param protectedDatabaseId The protected database OCID.
         * 
         * @return builder
         * 
         */
        public Builder protectedDatabaseId(String protectedDatabaseId) {
            return protectedDatabaseId(Output.of(protectedDatabaseId));
        }

        public GetProtectedDatabaseArgs build() {
            if ($.protectedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetProtectedDatabaseArgs", "protectedDatabaseId");
            }
            return $;
        }
    }

}
