// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrPlanPlanGroupStepUserDefinedStep {
    /**
     * @return The OCID of function to be invoked.  Example: `ocid1.fnfunc.oc1.iad.exampleocid2`
     * 
     */
    private @Nullable String functionId;
    /**
     * @return The region in which the function is deployed.  Example: `us-ashburn-1`
     * 
     */
    private @Nullable String functionRegion;
    /**
     * @return Information about an Object Storage script location for a user-defined step in a DR Plan.
     * 
     */
    private @Nullable List<DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations;
    /**
     * @return The request body for the function.  Example: `{ &#34;FnParam1&#34;, &#34;FnParam2&#34; }`
     * 
     */
    private @Nullable String requestBody;
    /**
     * @return The userid on the instance to be used for executing the script or command.  Example: `opc`
     * 
     */
    private @Nullable String runAsUser;
    /**
     * @return The OCID of the instance where this script or command should be executed.  Example: `ocid1.instance.oc1.phx.exampleocid1`
     * 
     */
    private @Nullable String runOnInstanceId;
    /**
     * @return The region of the instance where this script or command should be executed.  Example: `us-phoenix-1`
     * 
     */
    private @Nullable String runOnInstanceRegion;
    /**
     * @return The script name and arguments.  Example: `/usr/bin/python3 /home/opc/scripts/my_app_script.py arg1 arg2 arg3`
     * 
     */
    private @Nullable String scriptCommand;
    /**
     * @return The type of the step.
     * 
     */
    private @Nullable String stepType;

    private DrPlanPlanGroupStepUserDefinedStep() {}
    /**
     * @return The OCID of function to be invoked.  Example: `ocid1.fnfunc.oc1.iad.exampleocid2`
     * 
     */
    public Optional<String> functionId() {
        return Optional.ofNullable(this.functionId);
    }
    /**
     * @return The region in which the function is deployed.  Example: `us-ashburn-1`
     * 
     */
    public Optional<String> functionRegion() {
        return Optional.ofNullable(this.functionRegion);
    }
    /**
     * @return Information about an Object Storage script location for a user-defined step in a DR Plan.
     * 
     */
    public List<DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations() {
        return this.objectStorageScriptLocations == null ? List.of() : this.objectStorageScriptLocations;
    }
    /**
     * @return The request body for the function.  Example: `{ &#34;FnParam1&#34;, &#34;FnParam2&#34; }`
     * 
     */
    public Optional<String> requestBody() {
        return Optional.ofNullable(this.requestBody);
    }
    /**
     * @return The userid on the instance to be used for executing the script or command.  Example: `opc`
     * 
     */
    public Optional<String> runAsUser() {
        return Optional.ofNullable(this.runAsUser);
    }
    /**
     * @return The OCID of the instance where this script or command should be executed.  Example: `ocid1.instance.oc1.phx.exampleocid1`
     * 
     */
    public Optional<String> runOnInstanceId() {
        return Optional.ofNullable(this.runOnInstanceId);
    }
    /**
     * @return The region of the instance where this script or command should be executed.  Example: `us-phoenix-1`
     * 
     */
    public Optional<String> runOnInstanceRegion() {
        return Optional.ofNullable(this.runOnInstanceRegion);
    }
    /**
     * @return The script name and arguments.  Example: `/usr/bin/python3 /home/opc/scripts/my_app_script.py arg1 arg2 arg3`
     * 
     */
    public Optional<String> scriptCommand() {
        return Optional.ofNullable(this.scriptCommand);
    }
    /**
     * @return The type of the step.
     * 
     */
    public Optional<String> stepType() {
        return Optional.ofNullable(this.stepType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrPlanPlanGroupStepUserDefinedStep defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String functionId;
        private @Nullable String functionRegion;
        private @Nullable List<DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations;
        private @Nullable String requestBody;
        private @Nullable String runAsUser;
        private @Nullable String runOnInstanceId;
        private @Nullable String runOnInstanceRegion;
        private @Nullable String scriptCommand;
        private @Nullable String stepType;
        public Builder() {}
        public Builder(DrPlanPlanGroupStepUserDefinedStep defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.functionId = defaults.functionId;
    	      this.functionRegion = defaults.functionRegion;
    	      this.objectStorageScriptLocations = defaults.objectStorageScriptLocations;
    	      this.requestBody = defaults.requestBody;
    	      this.runAsUser = defaults.runAsUser;
    	      this.runOnInstanceId = defaults.runOnInstanceId;
    	      this.runOnInstanceRegion = defaults.runOnInstanceRegion;
    	      this.scriptCommand = defaults.scriptCommand;
    	      this.stepType = defaults.stepType;
        }

        @CustomType.Setter
        public Builder functionId(@Nullable String functionId) {
            this.functionId = functionId;
            return this;
        }
        @CustomType.Setter
        public Builder functionRegion(@Nullable String functionRegion) {
            this.functionRegion = functionRegion;
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageScriptLocations(@Nullable List<DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations) {
            this.objectStorageScriptLocations = objectStorageScriptLocations;
            return this;
        }
        public Builder objectStorageScriptLocations(DrPlanPlanGroupStepUserDefinedStepObjectStorageScriptLocation... objectStorageScriptLocations) {
            return objectStorageScriptLocations(List.of(objectStorageScriptLocations));
        }
        @CustomType.Setter
        public Builder requestBody(@Nullable String requestBody) {
            this.requestBody = requestBody;
            return this;
        }
        @CustomType.Setter
        public Builder runAsUser(@Nullable String runAsUser) {
            this.runAsUser = runAsUser;
            return this;
        }
        @CustomType.Setter
        public Builder runOnInstanceId(@Nullable String runOnInstanceId) {
            this.runOnInstanceId = runOnInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder runOnInstanceRegion(@Nullable String runOnInstanceRegion) {
            this.runOnInstanceRegion = runOnInstanceRegion;
            return this;
        }
        @CustomType.Setter
        public Builder scriptCommand(@Nullable String scriptCommand) {
            this.scriptCommand = scriptCommand;
            return this;
        }
        @CustomType.Setter
        public Builder stepType(@Nullable String stepType) {
            this.stepType = stepType;
            return this;
        }
        public DrPlanPlanGroupStepUserDefinedStep build() {
            final var o = new DrPlanPlanGroupStepUserDefinedStep();
            o.functionId = functionId;
            o.functionRegion = functionRegion;
            o.objectStorageScriptLocations = objectStorageScriptLocations;
            o.requestBody = requestBody;
            o.runAsUser = runAsUser;
            o.runOnInstanceId = runOnInstanceId;
            o.runOnInstanceRegion = runOnInstanceRegion;
            o.scriptCommand = scriptCommand;
            o.stepType = stepType;
            return o;
        }
    }
}