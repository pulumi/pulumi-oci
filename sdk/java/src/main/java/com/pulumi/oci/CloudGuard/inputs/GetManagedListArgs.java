// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetManagedListArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedListArgs Empty = new GetManagedListArgs();

    /**
     * The cloudguard list OCID to be passed in the request.
     * 
     */
    @Import(name="managedListId", required=true)
    private Output<String> managedListId;

    /**
     * @return The cloudguard list OCID to be passed in the request.
     * 
     */
    public Output<String> managedListId() {
        return this.managedListId;
    }

    private GetManagedListArgs() {}

    private GetManagedListArgs(GetManagedListArgs $) {
        this.managedListId = $.managedListId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedListArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedListArgs $;

        public Builder() {
            $ = new GetManagedListArgs();
        }

        public Builder(GetManagedListArgs defaults) {
            $ = new GetManagedListArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param managedListId The cloudguard list OCID to be passed in the request.
         * 
         * @return builder
         * 
         */
        public Builder managedListId(Output<String> managedListId) {
            $.managedListId = managedListId;
            return this;
        }

        /**
         * @param managedListId The cloudguard list OCID to be passed in the request.
         * 
         * @return builder
         * 
         */
        public Builder managedListId(String managedListId) {
            return managedListId(Output.of(managedListId));
        }

        public GetManagedListArgs build() {
            $.managedListId = Objects.requireNonNull($.managedListId, "expected parameter 'managedListId' to be non-null");
            return $;
        }
    }

}