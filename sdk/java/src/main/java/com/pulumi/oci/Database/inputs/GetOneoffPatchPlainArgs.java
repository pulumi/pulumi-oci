// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOneoffPatchPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOneoffPatchPlainArgs Empty = new GetOneoffPatchPlainArgs();

    /**
     * The one-off patch [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="oneoffPatchId", required=true)
    private String oneoffPatchId;

    /**
     * @return The one-off patch [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String oneoffPatchId() {
        return this.oneoffPatchId;
    }

    private GetOneoffPatchPlainArgs() {}

    private GetOneoffPatchPlainArgs(GetOneoffPatchPlainArgs $) {
        this.oneoffPatchId = $.oneoffPatchId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOneoffPatchPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOneoffPatchPlainArgs $;

        public Builder() {
            $ = new GetOneoffPatchPlainArgs();
        }

        public Builder(GetOneoffPatchPlainArgs defaults) {
            $ = new GetOneoffPatchPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param oneoffPatchId The one-off patch [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder oneoffPatchId(String oneoffPatchId) {
            $.oneoffPatchId = oneoffPatchId;
            return this;
        }

        public GetOneoffPatchPlainArgs build() {
            $.oneoffPatchId = Objects.requireNonNull($.oneoffPatchId, "expected parameter 'oneoffPatchId' to be non-null");
            return $;
        }
    }

}