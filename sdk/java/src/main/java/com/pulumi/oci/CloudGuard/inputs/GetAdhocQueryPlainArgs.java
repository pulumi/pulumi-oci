// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAdhocQueryPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAdhocQueryPlainArgs Empty = new GetAdhocQueryPlainArgs();

    /**
     * Adhoc query OCID.
     * 
     */
    @Import(name="adhocQueryId", required=true)
    private String adhocQueryId;

    /**
     * @return Adhoc query OCID.
     * 
     */
    public String adhocQueryId() {
        return this.adhocQueryId;
    }

    private GetAdhocQueryPlainArgs() {}

    private GetAdhocQueryPlainArgs(GetAdhocQueryPlainArgs $) {
        this.adhocQueryId = $.adhocQueryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAdhocQueryPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAdhocQueryPlainArgs $;

        public Builder() {
            $ = new GetAdhocQueryPlainArgs();
        }

        public Builder(GetAdhocQueryPlainArgs defaults) {
            $ = new GetAdhocQueryPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param adhocQueryId Adhoc query OCID.
         * 
         * @return builder
         * 
         */
        public Builder adhocQueryId(String adhocQueryId) {
            $.adhocQueryId = adhocQueryId;
            return this;
        }

        public GetAdhocQueryPlainArgs build() {
            if ($.adhocQueryId == null) {
                throw new MissingRequiredPropertyException("GetAdhocQueryPlainArgs", "adhocQueryId");
            }
            return $;
        }
    }

}
