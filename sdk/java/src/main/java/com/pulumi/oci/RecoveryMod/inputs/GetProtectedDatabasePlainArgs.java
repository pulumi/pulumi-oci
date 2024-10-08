// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetProtectedDatabasePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProtectedDatabasePlainArgs Empty = new GetProtectedDatabasePlainArgs();

    /**
     * The protected database OCID.
     * 
     */
    @Import(name="protectedDatabaseId", required=true)
    private String protectedDatabaseId;

    /**
     * @return The protected database OCID.
     * 
     */
    public String protectedDatabaseId() {
        return this.protectedDatabaseId;
    }

    private GetProtectedDatabasePlainArgs() {}

    private GetProtectedDatabasePlainArgs(GetProtectedDatabasePlainArgs $) {
        this.protectedDatabaseId = $.protectedDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProtectedDatabasePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProtectedDatabasePlainArgs $;

        public Builder() {
            $ = new GetProtectedDatabasePlainArgs();
        }

        public Builder(GetProtectedDatabasePlainArgs defaults) {
            $ = new GetProtectedDatabasePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param protectedDatabaseId The protected database OCID.
         * 
         * @return builder
         * 
         */
        public Builder protectedDatabaseId(String protectedDatabaseId) {
            $.protectedDatabaseId = protectedDatabaseId;
            return this;
        }

        public GetProtectedDatabasePlainArgs build() {
            if ($.protectedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetProtectedDatabasePlainArgs", "protectedDatabaseId");
            }
            return $;
        }
    }

}
