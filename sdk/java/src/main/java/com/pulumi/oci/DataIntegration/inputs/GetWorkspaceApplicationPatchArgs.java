// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetWorkspaceApplicationPatchArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkspaceApplicationPatchArgs Empty = new GetWorkspaceApplicationPatchArgs();

    /**
     * The application key.
     * 
     */
    @Import(name="applicationKey", required=true)
    private Output<String> applicationKey;

    /**
     * @return The application key.
     * 
     */
    public Output<String> applicationKey() {
        return this.applicationKey;
    }

    /**
     * The patch key.
     * 
     */
    @Import(name="patchKey", required=true)
    private Output<String> patchKey;

    /**
     * @return The patch key.
     * 
     */
    public Output<String> patchKey() {
        return this.patchKey;
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

    private GetWorkspaceApplicationPatchArgs() {}

    private GetWorkspaceApplicationPatchArgs(GetWorkspaceApplicationPatchArgs $) {
        this.applicationKey = $.applicationKey;
        this.patchKey = $.patchKey;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkspaceApplicationPatchArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkspaceApplicationPatchArgs $;

        public Builder() {
            $ = new GetWorkspaceApplicationPatchArgs();
        }

        public Builder(GetWorkspaceApplicationPatchArgs defaults) {
            $ = new GetWorkspaceApplicationPatchArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(Output<String> applicationKey) {
            $.applicationKey = applicationKey;
            return this;
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(String applicationKey) {
            return applicationKey(Output.of(applicationKey));
        }

        /**
         * @param patchKey The patch key.
         * 
         * @return builder
         * 
         */
        public Builder patchKey(Output<String> patchKey) {
            $.patchKey = patchKey;
            return this;
        }

        /**
         * @param patchKey The patch key.
         * 
         * @return builder
         * 
         */
        public Builder patchKey(String patchKey) {
            return patchKey(Output.of(patchKey));
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

        public GetWorkspaceApplicationPatchArgs build() {
            if ($.applicationKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchArgs", "applicationKey");
            }
            if ($.patchKey == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchArgs", "patchKey");
            }
            if ($.workspaceId == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchArgs", "workspaceId");
            }
            return $;
        }
    }

}
