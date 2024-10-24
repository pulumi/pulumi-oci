// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetWorkspaceFolderArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkspaceFolderArgs Empty = new GetWorkspaceFolderArgs();

    /**
     * The folder key.
     * 
     */
    @Import(name="folderKey", required=true)
    private Output<String> folderKey;

    /**
     * @return The folder key.
     * 
     */
    public Output<String> folderKey() {
        return this.folderKey;
    }

    /**
     * The workspace ID.
     * 
     */
    @Import(name="workspaceId", required=true)
    private Output<String> workspaceId;

    /**
     * @return The workspace ID.
     * 
     */
    public Output<String> workspaceId() {
        return this.workspaceId;
    }

    private GetWorkspaceFolderArgs() {}

    private GetWorkspaceFolderArgs(GetWorkspaceFolderArgs $) {
        this.folderKey = $.folderKey;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkspaceFolderArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkspaceFolderArgs $;

        public Builder() {
            $ = new GetWorkspaceFolderArgs();
        }

        public Builder(GetWorkspaceFolderArgs defaults) {
            $ = new GetWorkspaceFolderArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param folderKey The folder key.
         * 
         * @return builder
         * 
         */
        public Builder folderKey(Output<String> folderKey) {
            $.folderKey = folderKey;
            return this;
        }

        /**
         * @param folderKey The folder key.
         * 
         * @return builder
         * 
         */
        public Builder folderKey(String folderKey) {
            return folderKey(Output.of(folderKey));
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(Output<String> workspaceId) {
            $.workspaceId = workspaceId;
            return this;
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(String workspaceId) {
            return workspaceId(Output.of(workspaceId));
        }

        public GetWorkspaceFolderArgs build() {
            if ($.folderKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceFolderArgs", "folderKey");
            }
            if ($.workspaceId == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceFolderArgs", "workspaceId");
            }
            return $;
        }
    }

}
