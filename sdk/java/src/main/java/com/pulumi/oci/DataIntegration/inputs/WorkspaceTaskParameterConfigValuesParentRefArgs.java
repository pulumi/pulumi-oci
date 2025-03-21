// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceTaskParameterConfigValuesParentRefArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceTaskParameterConfigValuesParentRefArgs Empty = new WorkspaceTaskParameterConfigValuesParentRefArgs();

    /**
     * (Updatable) Key of the parent object.
     * 
     */
    @Import(name="parent")
    private @Nullable Output<String> parent;

    /**
     * @return (Updatable) Key of the parent object.
     * 
     */
    public Optional<Output<String>> parent() {
        return Optional.ofNullable(this.parent);
    }

    /**
     * (Updatable) Key of the root document object.
     * 
     */
    @Import(name="rootDocId")
    private @Nullable Output<String> rootDocId;

    /**
     * @return (Updatable) Key of the root document object.
     * 
     */
    public Optional<Output<String>> rootDocId() {
        return Optional.ofNullable(this.rootDocId);
    }

    private WorkspaceTaskParameterConfigValuesParentRefArgs() {}

    private WorkspaceTaskParameterConfigValuesParentRefArgs(WorkspaceTaskParameterConfigValuesParentRefArgs $) {
        this.parent = $.parent;
        this.rootDocId = $.rootDocId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceTaskParameterConfigValuesParentRefArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceTaskParameterConfigValuesParentRefArgs $;

        public Builder() {
            $ = new WorkspaceTaskParameterConfigValuesParentRefArgs();
        }

        public Builder(WorkspaceTaskParameterConfigValuesParentRefArgs defaults) {
            $ = new WorkspaceTaskParameterConfigValuesParentRefArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param parent (Updatable) Key of the parent object.
         * 
         * @return builder
         * 
         */
        public Builder parent(@Nullable Output<String> parent) {
            $.parent = parent;
            return this;
        }

        /**
         * @param parent (Updatable) Key of the parent object.
         * 
         * @return builder
         * 
         */
        public Builder parent(String parent) {
            return parent(Output.of(parent));
        }

        /**
         * @param rootDocId (Updatable) Key of the root document object.
         * 
         * @return builder
         * 
         */
        public Builder rootDocId(@Nullable Output<String> rootDocId) {
            $.rootDocId = rootDocId;
            return this;
        }

        /**
         * @param rootDocId (Updatable) Key of the root document object.
         * 
         * @return builder
         * 
         */
        public Builder rootDocId(String rootDocId) {
            return rootDocId(Output.of(rootDocId));
        }

        public WorkspaceTaskParameterConfigValuesParentRefArgs build() {
            return $;
        }
    }

}
