// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetWorkspaceExportRequestPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkspaceExportRequestPlainArgs Empty = new GetWorkspaceExportRequestPlainArgs();

    /**
     * The key of the object export object request
     * 
     */
    @Import(name="exportRequestKey", required=true)
    private String exportRequestKey;

    /**
     * @return The key of the object export object request
     * 
     */
    public String exportRequestKey() {
        return this.exportRequestKey;
    }

    /**
     * The workspace ID.
     * 
     */
    @Import(name="workspaceId", required=true)
    private String workspaceId;

    /**
     * @return The workspace ID.
     * 
     */
    public String workspaceId() {
        return this.workspaceId;
    }

    private GetWorkspaceExportRequestPlainArgs() {}

    private GetWorkspaceExportRequestPlainArgs(GetWorkspaceExportRequestPlainArgs $) {
        this.exportRequestKey = $.exportRequestKey;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkspaceExportRequestPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkspaceExportRequestPlainArgs $;

        public Builder() {
            $ = new GetWorkspaceExportRequestPlainArgs();
        }

        public Builder(GetWorkspaceExportRequestPlainArgs defaults) {
            $ = new GetWorkspaceExportRequestPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param exportRequestKey The key of the object export object request
         * 
         * @return builder
         * 
         */
        public Builder exportRequestKey(String exportRequestKey) {
            $.exportRequestKey = exportRequestKey;
            return this;
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(String workspaceId) {
            $.workspaceId = workspaceId;
            return this;
        }

        public GetWorkspaceExportRequestPlainArgs build() {
            if ($.exportRequestKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceExportRequestPlainArgs", "exportRequestKey");
            }
            if ($.workspaceId == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceExportRequestPlainArgs", "workspaceId");
            }
            return $;
        }
    }

}
