// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NotebookSessionNotebookSessionRuntimeConfigDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final NotebookSessionNotebookSessionRuntimeConfigDetailsArgs Empty = new NotebookSessionNotebookSessionRuntimeConfigDetailsArgs();

    /**
     * (Updatable) Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
     * 
     */
    @Import(name="customEnvironmentVariables")
    private @Nullable Output<Map<String,Object>> customEnvironmentVariables;

    /**
     * @return (Updatable) Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
     * 
     */
    public Optional<Output<Map<String,Object>>> customEnvironmentVariables() {
        return Optional.ofNullable(this.customEnvironmentVariables);
    }

    /**
     * (Updatable) Git configuration Details.
     * 
     */
    @Import(name="notebookSessionGitConfigDetails")
    private @Nullable Output<NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs> notebookSessionGitConfigDetails;

    /**
     * @return (Updatable) Git configuration Details.
     * 
     */
    public Optional<Output<NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs>> notebookSessionGitConfigDetails() {
        return Optional.ofNullable(this.notebookSessionGitConfigDetails);
    }

    private NotebookSessionNotebookSessionRuntimeConfigDetailsArgs() {}

    private NotebookSessionNotebookSessionRuntimeConfigDetailsArgs(NotebookSessionNotebookSessionRuntimeConfigDetailsArgs $) {
        this.customEnvironmentVariables = $.customEnvironmentVariables;
        this.notebookSessionGitConfigDetails = $.notebookSessionGitConfigDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NotebookSessionNotebookSessionRuntimeConfigDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NotebookSessionNotebookSessionRuntimeConfigDetailsArgs $;

        public Builder() {
            $ = new NotebookSessionNotebookSessionRuntimeConfigDetailsArgs();
        }

        public Builder(NotebookSessionNotebookSessionRuntimeConfigDetailsArgs defaults) {
            $ = new NotebookSessionNotebookSessionRuntimeConfigDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param customEnvironmentVariables (Updatable) Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
         * 
         * @return builder
         * 
         */
        public Builder customEnvironmentVariables(@Nullable Output<Map<String,Object>> customEnvironmentVariables) {
            $.customEnvironmentVariables = customEnvironmentVariables;
            return this;
        }

        /**
         * @param customEnvironmentVariables (Updatable) Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
         * 
         * @return builder
         * 
         */
        public Builder customEnvironmentVariables(Map<String,Object> customEnvironmentVariables) {
            return customEnvironmentVariables(Output.of(customEnvironmentVariables));
        }

        /**
         * @param notebookSessionGitConfigDetails (Updatable) Git configuration Details.
         * 
         * @return builder
         * 
         */
        public Builder notebookSessionGitConfigDetails(@Nullable Output<NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs> notebookSessionGitConfigDetails) {
            $.notebookSessionGitConfigDetails = notebookSessionGitConfigDetails;
            return this;
        }

        /**
         * @param notebookSessionGitConfigDetails (Updatable) Git configuration Details.
         * 
         * @return builder
         * 
         */
        public Builder notebookSessionGitConfigDetails(NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs notebookSessionGitConfigDetails) {
            return notebookSessionGitConfigDetails(Output.of(notebookSessionGitConfigDetails));
        }

        public NotebookSessionNotebookSessionRuntimeConfigDetailsArgs build() {
            return $;
        }
    }

}