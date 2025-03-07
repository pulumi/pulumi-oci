// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceTaskConfigProviderDelegateBindingArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceTaskConfigProviderDelegateBindingArgs Empty = new WorkspaceTaskConfigProviderDelegateBindingArgs();

    /**
     * (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    @Import(name="parameterValues")
    private @Nullable Output<WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs> parameterValues;

    public Optional<Output<WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs>> parameterValues() {
        return Optional.ofNullable(this.parameterValues);
    }

    private WorkspaceTaskConfigProviderDelegateBindingArgs() {}

    private WorkspaceTaskConfigProviderDelegateBindingArgs(WorkspaceTaskConfigProviderDelegateBindingArgs $) {
        this.key = $.key;
        this.parameterValues = $.parameterValues;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceTaskConfigProviderDelegateBindingArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceTaskConfigProviderDelegateBindingArgs $;

        public Builder() {
            $ = new WorkspaceTaskConfigProviderDelegateBindingArgs();
        }

        public Builder(WorkspaceTaskConfigProviderDelegateBindingArgs defaults) {
            $ = new WorkspaceTaskConfigProviderDelegateBindingArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param key (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        public Builder parameterValues(@Nullable Output<WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs> parameterValues) {
            $.parameterValues = parameterValues;
            return this;
        }

        public Builder parameterValues(WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs parameterValues) {
            return parameterValues(Output.of(parameterValues));
        }

        public WorkspaceTaskConfigProviderDelegateBindingArgs build() {
            return $;
        }
    }

}
