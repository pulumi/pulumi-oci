// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.oci.Integration.inputs.GetIntegrationInstanceArgs;
import com.pulumi.oci.Integration.inputs.GetIntegrationInstancePlainArgs;
import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesArgs;
import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesPlainArgs;
import com.pulumi.oci.Integration.outputs.GetIntegrationInstanceResult;
import com.pulumi.oci.Integration.outputs.GetIntegrationInstancesResult;
import com.pulumi.oci.Utilities;
import java.util.concurrent.CompletableFuture;

public final class IntegrationFunctions {
    /**
     * This data source provides details about a specific Integration Instance resource in Oracle Cloud Infrastructure Integration service.
     * 
     * Gets a IntegrationInstance by identifier
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstance = IntegrationFunctions.getIntegrationInstance(GetIntegrationInstanceArgs.builder()
     *             .integrationInstanceId(oci_integration_integration_instance.test_integration_instance().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetIntegrationInstanceResult> getIntegrationInstance(GetIntegrationInstanceArgs args) {
        return getIntegrationInstance(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Integration Instance resource in Oracle Cloud Infrastructure Integration service.
     * 
     * Gets a IntegrationInstance by identifier
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstance = IntegrationFunctions.getIntegrationInstance(GetIntegrationInstanceArgs.builder()
     *             .integrationInstanceId(oci_integration_integration_instance.test_integration_instance().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetIntegrationInstanceResult> getIntegrationInstancePlain(GetIntegrationInstancePlainArgs args) {
        return getIntegrationInstancePlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Integration Instance resource in Oracle Cloud Infrastructure Integration service.
     * 
     * Gets a IntegrationInstance by identifier
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstance = IntegrationFunctions.getIntegrationInstance(GetIntegrationInstanceArgs.builder()
     *             .integrationInstanceId(oci_integration_integration_instance.test_integration_instance().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetIntegrationInstanceResult> getIntegrationInstance(GetIntegrationInstanceArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Integration/getIntegrationInstance:getIntegrationInstance", TypeShape.of(GetIntegrationInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Integration Instance resource in Oracle Cloud Infrastructure Integration service.
     * 
     * Gets a IntegrationInstance by identifier
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstance = IntegrationFunctions.getIntegrationInstance(GetIntegrationInstanceArgs.builder()
     *             .integrationInstanceId(oci_integration_integration_instance.test_integration_instance().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetIntegrationInstanceResult> getIntegrationInstancePlain(GetIntegrationInstancePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Integration/getIntegrationInstance:getIntegrationInstance", TypeShape.of(GetIntegrationInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.
     * 
     * Returns a list of Integration Instances.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstances = IntegrationFunctions.getIntegrationInstances(GetIntegrationInstancesArgs.builder()
     *             .compartmentId(var_.compartment_id())
     *             .displayName(var_.integration_instance_display_name())
     *             .state(var_.integration_instance_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetIntegrationInstancesResult> getIntegrationInstances(GetIntegrationInstancesArgs args) {
        return getIntegrationInstances(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.
     * 
     * Returns a list of Integration Instances.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstances = IntegrationFunctions.getIntegrationInstances(GetIntegrationInstancesArgs.builder()
     *             .compartmentId(var_.compartment_id())
     *             .displayName(var_.integration_instance_display_name())
     *             .state(var_.integration_instance_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetIntegrationInstancesResult> getIntegrationInstancesPlain(GetIntegrationInstancesPlainArgs args) {
        return getIntegrationInstancesPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.
     * 
     * Returns a list of Integration Instances.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstances = IntegrationFunctions.getIntegrationInstances(GetIntegrationInstancesArgs.builder()
     *             .compartmentId(var_.compartment_id())
     *             .displayName(var_.integration_instance_display_name())
     *             .state(var_.integration_instance_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetIntegrationInstancesResult> getIntegrationInstances(GetIntegrationInstancesArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Integration/getIntegrationInstances:getIntegrationInstances", TypeShape.of(GetIntegrationInstancesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.
     * 
     * Returns a list of Integration Instances.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Integration.IntegrationFunctions;
     * import com.pulumi.oci.Integration.inputs.GetIntegrationInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testIntegrationInstances = IntegrationFunctions.getIntegrationInstances(GetIntegrationInstancesArgs.builder()
     *             .compartmentId(var_.compartment_id())
     *             .displayName(var_.integration_instance_display_name())
     *             .state(var_.integration_instance_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetIntegrationInstancesResult> getIntegrationInstancesPlain(GetIntegrationInstancesPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Integration/getIntegrationInstances:getIntegrationInstances", TypeShape.of(GetIntegrationInstancesResult.class), args, Utilities.withVersion(options));
    }
}