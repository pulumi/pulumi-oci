// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep {
    /**
     * @return The OCID of function to be invoked.  Example: `ocid1.fnfunc.oc1.iad.exampleocid2`
     * 
     */
    private String functionId;
    /**
     * @return The region in which the function is deployed.  Example: `us-ashburn-1`
     * 
     */
    private String functionRegion;
    /**
     * @return Information about an Object Storage script location for a user-defined step in a DR Plan.
     * 
     */
    private List<GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations;
    /**
     * @return The request body for the function.  Example: `{ &#34;FnParam1&#34;, &#34;FnParam2&#34; }`
     * 
     */
    private String requestBody;
    /**
     * @return The userid on the instance to be used for executing the script or command.  Example: `opc`
     * 
     */
    private String runAsUser;
    /**
     * @return The OCID of the instance where this script or command should be executed.  Example: `ocid1.instance.oc1.phx.exampleocid1`
     * 
     */
    private String runOnInstanceId;
    /**
     * @return The region of the instance where this script or command should be executed.  Example: `us-phoenix-1`
     * 
     */
    private String runOnInstanceRegion;
    /**
     * @return The script name and arguments.  Example: `/usr/bin/python3 /home/opc/scripts/my_app_script.py arg1 arg2 arg3`
     * 
     */
    private String scriptCommand;
    /**
     * @return The type of the step.
     * 
     */
    private String stepType;

    private GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep() {}
    /**
     * @return The OCID of function to be invoked.  Example: `ocid1.fnfunc.oc1.iad.exampleocid2`
     * 
     */
    public String functionId() {
        return this.functionId;
    }
    /**
     * @return The region in which the function is deployed.  Example: `us-ashburn-1`
     * 
     */
    public String functionRegion() {
        return this.functionRegion;
    }
    /**
     * @return Information about an Object Storage script location for a user-defined step in a DR Plan.
     * 
     */
    public List<GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations() {
        return this.objectStorageScriptLocations;
    }
    /**
     * @return The request body for the function.  Example: `{ &#34;FnParam1&#34;, &#34;FnParam2&#34; }`
     * 
     */
    public String requestBody() {
        return this.requestBody;
    }
    /**
     * @return The userid on the instance to be used for executing the script or command.  Example: `opc`
     * 
     */
    public String runAsUser() {
        return this.runAsUser;
    }
    /**
     * @return The OCID of the instance where this script or command should be executed.  Example: `ocid1.instance.oc1.phx.exampleocid1`
     * 
     */
    public String runOnInstanceId() {
        return this.runOnInstanceId;
    }
    /**
     * @return The region of the instance where this script or command should be executed.  Example: `us-phoenix-1`
     * 
     */
    public String runOnInstanceRegion() {
        return this.runOnInstanceRegion;
    }
    /**
     * @return The script name and arguments.  Example: `/usr/bin/python3 /home/opc/scripts/my_app_script.py arg1 arg2 arg3`
     * 
     */
    public String scriptCommand() {
        return this.scriptCommand;
    }
    /**
     * @return The type of the step.
     * 
     */
    public String stepType() {
        return this.stepType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String functionId;
        private String functionRegion;
        private List<GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations;
        private String requestBody;
        private String runAsUser;
        private String runOnInstanceId;
        private String runOnInstanceRegion;
        private String scriptCommand;
        private String stepType;
        public Builder() {}
        public Builder(GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep defaults) {
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
        public Builder functionId(String functionId) {
            this.functionId = Objects.requireNonNull(functionId);
            return this;
        }
        @CustomType.Setter
        public Builder functionRegion(String functionRegion) {
            this.functionRegion = Objects.requireNonNull(functionRegion);
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageScriptLocations(List<GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation> objectStorageScriptLocations) {
            this.objectStorageScriptLocations = Objects.requireNonNull(objectStorageScriptLocations);
            return this;
        }
        public Builder objectStorageScriptLocations(GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStepObjectStorageScriptLocation... objectStorageScriptLocations) {
            return objectStorageScriptLocations(List.of(objectStorageScriptLocations));
        }
        @CustomType.Setter
        public Builder requestBody(String requestBody) {
            this.requestBody = Objects.requireNonNull(requestBody);
            return this;
        }
        @CustomType.Setter
        public Builder runAsUser(String runAsUser) {
            this.runAsUser = Objects.requireNonNull(runAsUser);
            return this;
        }
        @CustomType.Setter
        public Builder runOnInstanceId(String runOnInstanceId) {
            this.runOnInstanceId = Objects.requireNonNull(runOnInstanceId);
            return this;
        }
        @CustomType.Setter
        public Builder runOnInstanceRegion(String runOnInstanceRegion) {
            this.runOnInstanceRegion = Objects.requireNonNull(runOnInstanceRegion);
            return this;
        }
        @CustomType.Setter
        public Builder scriptCommand(String scriptCommand) {
            this.scriptCommand = Objects.requireNonNull(scriptCommand);
            return this;
        }
        @CustomType.Setter
        public Builder stepType(String stepType) {
            this.stepType = Objects.requireNonNull(stepType);
            return this;
        }
        public GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep build() {
            final var o = new GetDrPlansDrPlanCollectionItemPlanGroupStepUserDefinedStep();
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