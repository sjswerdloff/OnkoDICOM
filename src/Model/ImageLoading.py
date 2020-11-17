"""
Format for allowed_classes:

"SOPClassUID" : {
    "name" : string
    "sliceable" : bool,
    "requires" : [SOPClassUID, ..]
}

Intention of this dictionary is that as SOP Classes are made compatible with OnkoDICOM, they should be defined here.
This refactors the ProgressBar.Extended.get_datasets(..) method with the purpose of making it more future-proof than
it's current state. As it stands, every time a new SOP Class is made compatible with OnkoDICOM, a new if/else branch
needs to be added to compensate. With this new function, new SOP Classes should be added to the allowed_classes
dictionary and the get_datasets() function should not need to be added to. (Of course realistically this is not the
case, however this alternative function promotes scalability and durability of the process).
"""
import collections
import math
import re
from multiprocessing import Queue, Process

from dicompylercore import dvhcalc
from pandas import np
from pydicom import dcmread
from pydicom.errors import InvalidDicomError

allowed_classes = {
    # CT Image
    "1.2.840.10008.5.1.4.1.1.2": {
        "name": "ct",
        "sliceable": True
    },
    # RT Structure Set
    "1.2.840.10008.5.1.4.1.1.481.3": {
        "name": "rtss",
        "sliceable": False
    },
    # RT Dose
    "1.2.840.10008.5.1.4.1.1.481.2": {
        "name": "rtdose",
        "sliceable" : False
    },
    # RT Plan
    "1.2.840.10008.5.1.4.1.1.481.5": {
        "name": "rtplan",
        "sliceable" : False
    },
    # RT Image
    "1.2.840.10008.5.1.4.1.1.481.1": {
        "name": "rtimage",
        "sliceable" : False
    },
    # MR Image
    "1.2.840.10008.5.1.4.1.1.4" : {
        "name": "mr",
        "sliceable" : True
    },
    # PET Image
    "1.2.840.10008.5.1.4.1.1.128" : {
        "name": "pet",
        "sliceable": True
    }
}


class NotRTSetError(Exception):
    pass


class NotAllowedClassError(Exception):
    pass


def get_datasets(filepath_list):
    """
    This function generates two dictionaries: the dictionary of PyDicom datasets, and the dictionary of filepaths.
    These two dictionaries are used in the PatientDictContainer model as the class attributes: 'dataset' and 'filepaths'
    The keys of both dictionaries are the dataset's slice number/RT modality. The values of the read_data_dict are
    PyDicom Dataset objects, and the values of the file_names_dict are filepaths pointing to the location of the .dcm
    file on the user's computer.
    :param filepath_list: List of all files to be searched.
    :return: Tuple (read_data_dict, file_names_dict)
    """
    read_data_dict = {}
    file_names_dict = {}

    slice_count = 0
    for file in natural_sort(filepath_list):
        try:
            read_file = dcmread(file)
        except InvalidDicomError:
            pass
        else:
            if read_file.SOPClassUID in allowed_classes:
                allowed_class = allowed_classes[read_file.SOPClassUID]
                if allowed_class["sliceable"]:
                    slice_name = slice_count
                    slice_count += 1
                else:
                    slice_name = allowed_class["name"]

                read_data_dict[slice_name] = read_file
                file_names_dict[slice_name] = file
            else:
                raise NotAllowedClassError

    sorted_read_data_dict, sorted_file_names_dict = image_stack_sort(read_data_dict, file_names_dict)

    return sorted_read_data_dict, sorted_file_names_dict


def img_stack_displacement(orientation, position):
    """
    Calculate the projection of the image position patient along the axis perpendicular to the images themselves,
    i.e. along the stack axis. Intended use is for the sorting key to sort a stack of image datasets so that they are in
    order, regardless of whether the images are axial, coronal, or sagittal, and independent from the order in which the
    images were read in.
    :param orientation: List of strings with six elements, the image orientation patient value from the dataset.
    :param position: List of strings with three elements, the image position value from the dataset.
    :return: Float of the image position patient along the image stack axis.
    """
    ds_orient_x = orientation[0:3]
    ds_orient_y = orientation[3:6]
    orient_x = np.array(list(map(float, ds_orient_x)))
    orient_y = np.array(list(map(float, ds_orient_y)))
    orient_z = np.cross(orient_x, orient_y)
    img_pos_patient = np.array(list(map(float, position)))
    displacement = orient_z.dot(img_pos_patient)

    return displacement


def get_dict_sort_on_displacement(item):
    """
    :param item: dictionary key, value item with value of a PyDicom dataset
    :return: Float of the projection of the image position patient on the axis through the image stack
    """
    img_dataset = item[1]
    orientation = img_dataset.ImageOrientationPatient
    position = img_dataset.ImagePositionPatient
    sort_key = img_stack_displacement(orientation, position)

    return sort_key


def image_stack_sort(read_data_dict, file_names_dict):
    """
    Sort the read_data_dict and file_names_dict by order of displacement along the image stack axis.
    For axial images this is by the Z coordinate.
    :return: Tuple of sorted dictionaries
    """
    new_image_dict = {key: value for (key, value) in read_data_dict.items() if str(key).isnumeric()}
    new_image_file_names_dict = {key: value for (key, value) in file_names_dict.items() if str(key).isnumeric()}
    new_non_image_dict = {key: value for (key, value) in read_data_dict.items() if not str(key).isnumeric()}
    new_non_image_file_names_dict = {key: value for (key, value) in file_names_dict.items() if not str(key).isnumeric()}

    new_items = new_image_dict.items()
    sorted_dict_on_displacement = sorted(new_items, key=get_dict_sort_on_displacement, reverse=True)

    new_read_data_dict = {}
    new_file_names_dict = {}

    i = 0
    for sorted_dataset in sorted_dict_on_displacement:
        new_read_data_dict[i] = sorted_dataset[1]
        original_index = sorted_dataset[0]
        new_file_names_dict[i] = new_image_file_names_dict[original_index]
        i += 1

    new_read_data_dict.update(new_non_image_dict)
    new_file_names_dict.update(new_non_image_file_names_dict)

    return new_read_data_dict, new_file_names_dict


def is_dataset_dicom_rt(read_data_dict):
    """
    Tests if a read_data_dict produced by get_datasets(..) is a DICOM-RT set.
    :param read_data_dict: Dictionary of DICOM dataset objects.
    :return:  True if read_data_dict can be considered a complete DICOM-RT object.
    """
    class_names = []

    for key, item in read_data_dict.items():
        if allowed_classes[item.SOPClassUID]["name"] not in class_names:
            class_names.append(allowed_classes[item.SOPClassUID]["name"])

    class_names.sort()
    return class_names == ["ct", "rtdose", "rtplan", "rtss"]


def natural_sort(strings):
    """
    Sort filenames.
    :param strings:   List of strings.
    :return: Sorted list of strings.
    """
    def convert(text): return int(text) if text.isdigit() else text.lower()

    def alphanum_key(key): return [convert(c) for c in re.split('([0-9]+)', key)]

    return sorted(strings, key=alphanum_key)


def get_roi_info(dataset_rtss):
    """
    :param dataset_rtss: RTSTRUCT DICOM dataset object.
    :return: Dictionary of ROI information.
    """
    dict_roi = {}
    for sequence in dataset_rtss.StructureSetROISequence:
        dict_temp = {}
        dict_temp['uid'] = sequence.ReferencedFrameOfReferenceUID
        dict_temp['name'] = sequence.ROIName
        dict_temp['algorithm'] = sequence.ROIGenerationAlgorithm
        dict_roi[sequence.ROINumber] = dict_temp

    return dict_roi


def get_thickness_dict(dataset_rtss, read_data_dict):
    """
    Calculates and returns thicknesses for all ROIs in the RTSTRUCT that only contain one contour.
    The process used to calculate thickness is courtesy of @sjswerdloff
    :param dataset_rtss: RTSTRUCT DICOM dataset object.
    :param read_data_dict:
    :return: Dictionary of ROI thicknesses where the key is the ROI number and the value is the thickness.
    """
    # Generate a dict where keys are ROI numbers for structures with only one contour.
    # Value of each key is the SOPInstanceUID of the CT slice the contour is positioned on.
    single_contour_rois = {}
    for contour in dataset_rtss.ROIContourSequence:
        if len(contour.ContourSequence) == 1:
            single_contour_rois[contour.ReferencedROINumber] = \
                contour.ContourSequence[0].ContourImageSequence[0].ReferencedSOPInstanceUID

    dict_thickness = {}
    for roi_number, sop_instance_uid in single_contour_rois.items():
        # Get the slice numbers the slices before and after the slice the ROI is positioned on.
        slice_key = None
        for key, ds in read_data_dict.items():
            if ds.SOPInstanceUID == sop_instance_uid:
                slice_key = key

        # Get the Image Position (Patient) from the two slices.
        try:
            position_before = np.array(read_data_dict[slice_key - 1].ImagePositionPatient)
            position_after = np.array(read_data_dict[slice_key + 1].ImagePositionPatient)

            # Calculate displacement between slices
            displacement = position_after - position_before

        except KeyError:
            # If the image slice is either at the top of bottom of the set, use the length of the displacement to the
            # adjacent slice as the thickness.
            if slice_key == 1:  # If the image slice is at the bottom of the set.
                position_current = np.array(read_data_dict[slice_key].ImagePositionPatient)
                position_after = np.array(read_data_dict[slice_key + 1].ImagePositionPatient)
                displacement = position_after - position_current
            else:
                position_current = np.array(read_data_dict[slice_key].ImagePositionPatient)
                position_before = np.array(read_data_dict[slice_key - 1].ImagePositionPatient)
                displacement = position_current - position_before

        # Finally, calculate thickness.
        thickness = math.sqrt(displacement[0] * displacement[0]
                              + displacement[1] * displacement[1]
                              + displacement[2] * displacement[2]) / 2

        dict_thickness[roi_number] = thickness

    return dict_thickness


def calc_dvhs(dataset_rtss, dataset_rtdose, rois, dict_thickness, interrupt_flag, dose_limit=None):
    """
    :param dataset_rtss: RTSTRUCT DICOM dataset object.
    :param dataset_rtdose: RTDOSE DICOM dataset object.
    :param rois: Dictionary of ROI information.
    :param dict_thickness: Dictionary where the keys are ROI numbers and the values are thicknesses of the ROI.
    :param interrupt_flag: A threading.Event() object that tells the function to stop calculation.
    :param dose_limit: Limit of dose for DVH calculation.
    :return: Dictionary of all the DVHs of all the ROIs of the patient.
    """
    dict_dvh = {}
    roi_list = []
    for key in rois:
        roi_list.append(key)

    for roi in roi_list:
        thickness = None
        if roi in dict_thickness:
            thickness = dict_thickness[roi]
        dict_dvh[roi] = dvhcalc.get_dvh(dataset_rtss, dataset_rtdose, roi, dose_limit, thickness=thickness)
        if interrupt_flag.is_set():  # Stop calculating at the next DVH.
            return

    return dict_dvh


def calc_dvh_worker(rtss, dose, roi, queue, thickness, dose_limit=None):
    dvh = {}
    dvh[roi] = dvhcalc.get_dvh(rtss, dose, roi, dose_limit, thickness=thickness)
    queue.put(dvh)


def multi_calc_dvh(dataset_rtss, dataset_rtdose, rois, dict_thickness, dose_limit=None):
    """
    Multiprocessing variant of calc_dvh for fork-based platforms.
    """
    queue = Queue()
    processes = []
    dict_dvh = {}

    roi_list = []
    for key in rois:
        roi_list.append(key)

    for i in range(len(roi_list)):
        thickness = None
        if roi_list[i] in dict_thickness:
            thickness = dict_thickness[roi_list[i]]
        p = Process(target=calc_dvh_worker, args=(dataset_rtss, dataset_rtdose, roi_list[i],
                                                  queue, thickness, dose_limit,))
        processes.append(p)
        p.start()

    for process in processes:
        dvh = queue.get()
        dict_dvh.update(dvh)

    for process in processes:
        process.join()

    return dict_dvh


def converge_to_0_dvh(raw_dvh):
    """
    :param raw_dvh: Dictionary produced by calc_dvhs(..) function.
    :return: Dictionary of bincenters and counts (x and y of DVH)
    """
    res = {}
    zeros = np.zeros(3)
    for roi in raw_dvh:
        res[roi] = {}
        dvh = raw_dvh[roi]

        # The last value of DVH is not equal to 0
        if len(dvh.counts) > 0:
            if dvh.counts[-1] != 0:
                tmp_bincenters = []
                for i in range(3):
                    tmp_bincenters.append(dvh.bincenters[-1] + i)

                tmp_bincenters = np.array(tmp_bincenters)
                tmp_bincenters = np.concatenate(
                    (dvh.bincenters.flatten(), tmp_bincenters))
                bincenters = np.array(tmp_bincenters)
                counts = np.concatenate(
                    (dvh.counts.flatten(), np.array(zeros)))

            # The last value of DVH is equal to 0
            else:
                bincenters = dvh.bincenters
                counts = dvh.counts
        else:
            bincenters = dvh.bincenters
            counts = dvh.counts

        res[roi]['bincenters'] = bincenters
        res[roi]['counts'] = counts

    return res


def get_raw_contour_data(dataset_rtss):
    """
    :param dataset_rtss: RTSTRUCT DICOM dataset object.
    :return: Tuple (dict_roi, dict_numpoints) raw contour data of the ROIs.
    """
    dict_id = {}
    for i, elem in enumerate(dataset_rtss.StructureSetROISequence):
        roi_number = elem.ROINumber
        roi_name = elem.ROIName
        dict_id[roi_number] = roi_name

    dict_roi = {}
    dict_numpoints = {}
    for roi in dataset_rtss.ROIContourSequence:
        ReferencedROINumber = roi.ReferencedROINumber
        ROIName = dict_id[ReferencedROINumber]
        dict_contour = collections.defaultdict(list)
        roi_points_count = 0
        if 'ContourSequence' in roi:
            for slice in roi.ContourSequence:
                if 'ContourImageSequence' in slice:
                    for contour_img in slice.ContourImageSequence:
                        ReferencedSOPInstanceUID = contour_img.ReferencedSOPInstanceUID
                    ContourGeometricType = slice.ContourGeometricType
                    NumberOfContourPoints = slice.NumberOfContourPoints
                    roi_points_count += int(NumberOfContourPoints)
                    ContourData = slice.ContourData
                    dict_contour[ReferencedSOPInstanceUID].append(ContourData)
        dict_roi[ROIName] = dict_contour
        dict_numpoints[ROIName] = roi_points_count

    return dict_roi, dict_numpoints


def calculate_matrix(img_ds):
    # Physical distance (in mm) between the center of each image pixel, specified by a numeric pair
    # - adjacent row spacing (delimiter) adjacent column spacing.
    dist_row = img_ds.PixelSpacing[0]
    dist_col = img_ds.PixelSpacing[1]
    # The direction cosines of the first row and the first column with respect to the patient.
    # 6 values inside: [Xx, Xy, Xz, Yx, Yy, Yz]
    orientation = img_ds.ImageOrientationPatient
    # The x, y, and z coordinates of the upper left hand corner
    # (center of the first voxel transmitted) of the image, in mm.
    # 3 values: [Sx, Sy, Sz]
    position = img_ds.ImagePositionPatient

    # Equation C.7.6.2.1-1.
    # https://dicom.innolitics.com/ciods/rt-structure-set/roi-contour/30060039/30060040/30060050
    matrix_M = np.matrix(
        [[orientation[0] * dist_row, orientation[3] * dist_col, 0, position[0]],
         [orientation[1] * dist_row, orientation[4] * dist_col, 0, position[1]],
         [orientation[2] * dist_row, orientation[5] * dist_col, 0, position[2]],
         [0, 0, 0, 1]]
    )
    x = []
    y = []
    for i in range(0, img_ds.Columns):
        i_mat = matrix_M * np.matrix([[i], [0], [0], [1]])
        x.append(float(i_mat[0]))

    for j in range(0, img_ds.Rows):
        j_mat = matrix_M * np.matrix([[0], [j], [0], [1]])
        y.append(float(j_mat[1]))

    return np.array(x), np.array(y)


def get_pixluts(read_data_dict):
    """
    :param read_data_dict: Dictionary of all DICOM dataset objects.
    :return: Dictionary of pixluts for the transformation from 3D to 2D.
    """
    dict_pixluts = {}
    non_img_type = ['rtdose', 'rtplan', 'rtss', 'rtimage']
    for ds in read_data_dict:
        if ds not in non_img_type:
            img_ds = read_data_dict[ds]
            pixlut = calculate_matrix(img_ds)
            dict_pixluts[img_ds.SOPInstanceUID] = pixlut

    return dict_pixluts
