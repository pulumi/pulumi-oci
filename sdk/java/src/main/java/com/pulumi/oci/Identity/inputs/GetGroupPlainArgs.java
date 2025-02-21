// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetGroupPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetGroupPlainArgs Empty = new GetGroupPlainArgs();

    /**
     * The OCID of the group.
     * 
     */
    @Import(name="groupId", required=true)
    private String groupId;

    /**
     * @return The OCID of the group.
     * 
     */
    public String groupId() {
        return this.groupId;
    }

    private GetGroupPlainArgs() {}

    private GetGroupPlainArgs(GetGroupPlainArgs $) {
        this.groupId = $.groupId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetGroupPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetGroupPlainArgs $;

        public Builder() {
            $ = new GetGroupPlainArgs();
        }

        public Builder(GetGroupPlainArgs defaults) {
            $ = new GetGroupPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param groupId The OCID of the group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            $.groupId = groupId;
            return this;
        }

        public GetGroupPlainArgs build() {
            if ($.groupId == null) {
                throw new MissingRequiredPropertyException("GetGroupPlainArgs", "groupId");
            }
            return $;
        }
    }

}
