// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetPrivateApplicationPackagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateApplicationPackagePlainArgs Empty = new GetPrivateApplicationPackagePlainArgs();

    /**
     * The unique identifier for the private application package.
     * 
     */
    @Import(name="privateApplicationPackageId", required=true)
    private String privateApplicationPackageId;

    /**
     * @return The unique identifier for the private application package.
     * 
     */
    public String privateApplicationPackageId() {
        return this.privateApplicationPackageId;
    }

    private GetPrivateApplicationPackagePlainArgs() {}

    private GetPrivateApplicationPackagePlainArgs(GetPrivateApplicationPackagePlainArgs $) {
        this.privateApplicationPackageId = $.privateApplicationPackageId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateApplicationPackagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateApplicationPackagePlainArgs $;

        public Builder() {
            $ = new GetPrivateApplicationPackagePlainArgs();
        }

        public Builder(GetPrivateApplicationPackagePlainArgs defaults) {
            $ = new GetPrivateApplicationPackagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param privateApplicationPackageId The unique identifier for the private application package.
         * 
         * @return builder
         * 
         */
        public Builder privateApplicationPackageId(String privateApplicationPackageId) {
            $.privateApplicationPackageId = privateApplicationPackageId;
            return this;
        }

        public GetPrivateApplicationPackagePlainArgs build() {
            $.privateApplicationPackageId = Objects.requireNonNull($.privateApplicationPackageId, "expected parameter 'privateApplicationPackageId' to be non-null");
            return $;
        }
    }

}