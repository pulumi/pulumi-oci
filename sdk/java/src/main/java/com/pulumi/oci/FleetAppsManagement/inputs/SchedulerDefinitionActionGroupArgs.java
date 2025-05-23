// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SchedulerDefinitionActionGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulerDefinitionActionGroupArgs Empty = new SchedulerDefinitionActionGroupArgs();

    /**
     * (Updatable) Application Type associated. Only applicable if type is ENVIRONMENT.
     * 
     */
    @Import(name="applicationType")
    private @Nullable Output<String> applicationType;

    /**
     * @return (Updatable) Application Type associated. Only applicable if type is ENVIRONMENT.
     * 
     */
    public Optional<Output<String>> applicationType() {
        return Optional.ofNullable(this.applicationType);
    }

    /**
     * (Updatable) LifeCycle Operation
     * 
     */
    @Import(name="lifecycleOperation")
    private @Nullable Output<String> lifecycleOperation;

    /**
     * @return (Updatable) LifeCycle Operation
     * 
     */
    public Optional<Output<String>> lifecycleOperation() {
        return Optional.ofNullable(this.lifecycleOperation);
    }

    /**
     * (Updatable) Product associated. Only applicable if type is PRODUCT.
     * 
     */
    @Import(name="product")
    private @Nullable Output<String> product;

    /**
     * @return (Updatable) Product associated. Only applicable if type is PRODUCT.
     * 
     */
    public Optional<Output<String>> product() {
        return Optional.ofNullable(this.product);
    }

    /**
     * (Updatable) Provide the ID of the resource. Example fleet ID.
     * 
     */
    @Import(name="resourceId", required=true)
    private Output<String> resourceId;

    /**
     * @return (Updatable) Provide the ID of the resource. Example fleet ID.
     * 
     */
    public Output<String> resourceId() {
        return this.resourceId;
    }

    /**
     * (Updatable) ID of the runbook
     * 
     */
    @Import(name="runbookId", required=true)
    private Output<String> runbookId;

    /**
     * @return (Updatable) ID of the runbook
     * 
     */
    public Output<String> runbookId() {
        return this.runbookId;
    }

    /**
     * (Updatable) Provide subjects that need to be considered for the schedule.
     * 
     */
    @Import(name="subjects")
    private @Nullable Output<List<String>> subjects;

    /**
     * @return (Updatable) Provide subjects that need to be considered for the schedule.
     * 
     */
    public Optional<Output<List<String>>> subjects() {
        return Optional.ofNullable(this.subjects);
    }

    /**
     * (Updatable) Provide the target if schedule is created against the target
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return (Updatable) Provide the target if schedule is created against the target
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    /**
     * (Updatable) ActionGroup Type associated.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) ActionGroup Type associated.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private SchedulerDefinitionActionGroupArgs() {}

    private SchedulerDefinitionActionGroupArgs(SchedulerDefinitionActionGroupArgs $) {
        this.applicationType = $.applicationType;
        this.lifecycleOperation = $.lifecycleOperation;
        this.product = $.product;
        this.resourceId = $.resourceId;
        this.runbookId = $.runbookId;
        this.subjects = $.subjects;
        this.targetId = $.targetId;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulerDefinitionActionGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulerDefinitionActionGroupArgs $;

        public Builder() {
            $ = new SchedulerDefinitionActionGroupArgs();
        }

        public Builder(SchedulerDefinitionActionGroupArgs defaults) {
            $ = new SchedulerDefinitionActionGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationType (Updatable) Application Type associated. Only applicable if type is ENVIRONMENT.
         * 
         * @return builder
         * 
         */
        public Builder applicationType(@Nullable Output<String> applicationType) {
            $.applicationType = applicationType;
            return this;
        }

        /**
         * @param applicationType (Updatable) Application Type associated. Only applicable if type is ENVIRONMENT.
         * 
         * @return builder
         * 
         */
        public Builder applicationType(String applicationType) {
            return applicationType(Output.of(applicationType));
        }

        /**
         * @param lifecycleOperation (Updatable) LifeCycle Operation
         * 
         * @return builder
         * 
         */
        public Builder lifecycleOperation(@Nullable Output<String> lifecycleOperation) {
            $.lifecycleOperation = lifecycleOperation;
            return this;
        }

        /**
         * @param lifecycleOperation (Updatable) LifeCycle Operation
         * 
         * @return builder
         * 
         */
        public Builder lifecycleOperation(String lifecycleOperation) {
            return lifecycleOperation(Output.of(lifecycleOperation));
        }

        /**
         * @param product (Updatable) Product associated. Only applicable if type is PRODUCT.
         * 
         * @return builder
         * 
         */
        public Builder product(@Nullable Output<String> product) {
            $.product = product;
            return this;
        }

        /**
         * @param product (Updatable) Product associated. Only applicable if type is PRODUCT.
         * 
         * @return builder
         * 
         */
        public Builder product(String product) {
            return product(Output.of(product));
        }

        /**
         * @param resourceId (Updatable) Provide the ID of the resource. Example fleet ID.
         * 
         * @return builder
         * 
         */
        public Builder resourceId(Output<String> resourceId) {
            $.resourceId = resourceId;
            return this;
        }

        /**
         * @param resourceId (Updatable) Provide the ID of the resource. Example fleet ID.
         * 
         * @return builder
         * 
         */
        public Builder resourceId(String resourceId) {
            return resourceId(Output.of(resourceId));
        }

        /**
         * @param runbookId (Updatable) ID of the runbook
         * 
         * @return builder
         * 
         */
        public Builder runbookId(Output<String> runbookId) {
            $.runbookId = runbookId;
            return this;
        }

        /**
         * @param runbookId (Updatable) ID of the runbook
         * 
         * @return builder
         * 
         */
        public Builder runbookId(String runbookId) {
            return runbookId(Output.of(runbookId));
        }

        /**
         * @param subjects (Updatable) Provide subjects that need to be considered for the schedule.
         * 
         * @return builder
         * 
         */
        public Builder subjects(@Nullable Output<List<String>> subjects) {
            $.subjects = subjects;
            return this;
        }

        /**
         * @param subjects (Updatable) Provide subjects that need to be considered for the schedule.
         * 
         * @return builder
         * 
         */
        public Builder subjects(List<String> subjects) {
            return subjects(Output.of(subjects));
        }

        /**
         * @param subjects (Updatable) Provide subjects that need to be considered for the schedule.
         * 
         * @return builder
         * 
         */
        public Builder subjects(String... subjects) {
            return subjects(List.of(subjects));
        }

        /**
         * @param targetId (Updatable) Provide the target if schedule is created against the target
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId (Updatable) Provide the target if schedule is created against the target
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        /**
         * @param type (Updatable) ActionGroup Type associated.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) ActionGroup Type associated.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public SchedulerDefinitionActionGroupArgs build() {
            if ($.resourceId == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionActionGroupArgs", "resourceId");
            }
            if ($.runbookId == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionActionGroupArgs", "runbookId");
            }
            return $;
        }
    }

}
