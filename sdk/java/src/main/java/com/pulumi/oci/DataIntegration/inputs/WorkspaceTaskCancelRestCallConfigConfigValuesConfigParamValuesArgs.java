// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs Empty = new WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs();

    @Import(name="requestPayload")
    private @Nullable Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs> requestPayload;

    public Optional<Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs>> requestPayload() {
        return Optional.ofNullable(this.requestPayload);
    }

    @Import(name="requestUrl")
    private @Nullable Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs> requestUrl;

    public Optional<Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs>> requestUrl() {
        return Optional.ofNullable(this.requestUrl);
    }

    private WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs() {}

    private WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs(WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs $) {
        this.requestPayload = $.requestPayload;
        this.requestUrl = $.requestUrl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs $;

        public Builder() {
            $ = new WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs();
        }

        public Builder(WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs defaults) {
            $ = new WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs(Objects.requireNonNull(defaults));
        }

        public Builder requestPayload(@Nullable Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs> requestPayload) {
            $.requestPayload = requestPayload;
            return this;
        }

        public Builder requestPayload(WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs requestPayload) {
            return requestPayload(Output.of(requestPayload));
        }

        public Builder requestUrl(@Nullable Output<WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs> requestUrl) {
            $.requestUrl = requestUrl;
            return this;
        }

        public Builder requestUrl(WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs requestUrl) {
            return requestUrl(Output.of(requestUrl));
        }

        public WorkspaceTaskCancelRestCallConfigConfigValuesConfigParamValuesArgs build() {
            return $;
        }
    }

}
