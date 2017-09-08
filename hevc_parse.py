#usr/bin/env python

import os
import sys
import bitstring 
import shutil
import random
import pandas as pd
import subprocess

from bitstring import BitStream, BitArray, ConstBitStream, pack
name=str(sys.argv[1])
name=name.split('.')[0]
s=BitStream(filename=str(sys.argv[1]))		       # take the file name
posu=None
if (len(sys.argv)==3):
	posu=str(sys.argv[2])
pcksTOPs=list(s.findall('0x00000001', bytealigned=True))   # All frame headers includes VPS,SPS and PPS
pcks=list(s.findall('0x000001', bytealigned=True))         # Find NAL for slices includes VPS,SPS,PPS and SEI
pcksAdj=[p+8 for p in pcksTOPs]                            # +8 to bring the postion to first of 0x00'000001 from 0x'00000001) to compare positions found 
b=set(pcksAdj)
allowedIDS=[i for i, item in enumerate(pcks) if item not in b]
del allowedIDS[0:12] 										   # exclude SEI NAL which has delimiter 0x000001



def conceal_p1(s,posi):
	#constants:
	NAL_header = 16
	NAL_delimiter = 24
	slices_per_frame = 12
	slices_copy = slices_per_frame
	NumBytesNALunit = (pcks[posi+1]-pcks[posi])/8
	slice_rmv = ((posi+1) - 4) % slices_per_frame
	if slice_rmv == 0:
		slice_rmv = slices_per_frame
	frame_rmv  = ((posi+1) / slices_per_frame) +1	#s.pos = pcks[posi]+24+16
	final=pcks[posi]+56			   # start after the delimiter
	s.pos=final
	nbits1=pcks[posi+1]-pcks[posi]-56	   # exclude 2 byte file header and 3 byte delimiter
	s.pos=final
	del s[final:final+nbits1]				   # s.overwrite can also be used

	# Copying bits
	previous=pcks[posi-1]+56
	nbits2=pcks[posi]-pcks[posi-1]-56
	s.pos=previous
	copied=s.read(nbits2)

	#Replace
	s.pos=final
	s.insert(copied)
	print('Its a P1 type, slice copy concealment in use')
	output_file = 'D:\Action\Concealed\{}_{}_{}_{}.bin'.format(name,str(posi+1),NumBytesNALunit,slice_rmv)
	A=[NumBytesNALunit,slice_rmv]
	f = open(output_file, 'wb')
	s.tofile(f)
	return A

def conceal(s,posi):
	#constants:
	NAL_header = 16
	NAL_delimiter = 24
	slices_per_frame = 12
	slices_copy = slices_per_frame
	NumBytesNALunit = (pcks[posi+1]-pcks[posi])/8
	slice_rmv = ((posi+1) - 4) % slices_per_frame
	if slice_rmv == 0:
		slice_rmv = slices_per_frame
	frame_rmv  = ((posi+1) / slices_per_frame) +1	#s.pos = pcks[posi]+24+16
	s.pos = pcks[posi] #current position is the start of the header ( +24 to skip the header)
	forbidden_zero_bit_rmv,nal_unit_type_rmv,nuh_layer_id_rmv,nuh_temporal_id_plus1_rmv=s.readlist(['pad:24','1','6','6','3']) #pad to skip the first 24 bytes
	s.pos = pcks[posi-slices_copy] #current position is the start of the header ( +24 to skip the header)
	forbidden_zero_bit_ref,nal_unit_type_ref,nuh_layer_id_ref,nuh_temporal_id_plus1_ref=s.readlist(['pad:24','1','6','6','3']) #pad to skip the first 24 bytes
	first_slice_segment = s.readlist('1')
	if nal_unit_type_ref == 19 or nal_unit_type_ref == 20 :
		slices_copy = 2*slices_per_frame #copy from the frame vefore IDR
		print('copied from frame before the IDR')
	else:
		slices_copy = slices_per_frame
		print('normal copy')
	position_ref = pcks[posi - slices_copy] + 24 + 16
	position_rmv = pcks[posi] + 24 + 16
	#payload of slices
	sizeofpayload_ref =  pcks[posi + 1 - slices_copy] - (pcks[posi - slices_copy] +24+16)
	sizeofpayload_rmv =  pcks[posi + 1] - (pcks[posi] +24+16) 
	#copying the payload from reference slice
	s.pos = position_ref 							#move the reader past the delimiter and heade
	copy_bits_reference = s.read(sizeofpayload_ref) #these are the slice copy bits
	#removing payload of the slice
	s.pos = position_rmv
	del s[position_rmv : pcks[posi+1]]
	s.pos = pcks[posi] + 24 + 16
	#copying payload from the refence slice, header is retaine
	s.insert(copy_bits_reference)
	s.pos = 0
	output_file = 'D:\Action\Concealed\{}_{}_{}_{}.bin'.format(name,str(posi+1),NumBytesNALunit,slice_rmv)
	A=[NumBytesNALunit,slice_rmv]
	f = open(output_file, 'wb')
	s.tofile(f)
	return A

def find_frame(posi,rem):
	if (int(posi%600)<28 and int(posi%600)>15):
		return 'P1'
	else:
		post=int((int((posi-4-24*rem)% 48))/12)
		return	{
		    0: 'RB',
		    1: 'NRB',
		    2: 'NRB',
		    3: 'P2',
		}.get(post, None)


def find_poc(posi,rem):
	re=int(((posi-4-24*rem)%48))
	qu=int(((posi-4-24*rem)/48))
	poc=qu*4+1+2*rem

	if (int(posi%600)<28 and int(posi%600)>15):
		return (poc+2)
	elif re==0:
		return poc+4
	else:
		re2=int(re/12)
		if re2==0:
			return poc
		elif re2==1:
			return poc-1
		elif re2==2:
			return poc+1
		else:
			return poc+6

def extract_frame(name,ret2,A):
	NAME_in=str(name)+str('.yuv')
	NAME_out='D:\Action\Images\{}_{}.bmp'.format(ret2,A[1])
	print(NAME_in)
	print(NAME_out)
	command='ffmpeg -video_size 1280x720 -framerate 50 -i {} -vf extractplanes=y -vf "select=gte(n\,%i)" -vframes 1 {}'.format(NAME_in,NAME_out)%(ret2)

	#command=["ffmpeg","-f", "rawvideo","-s",'1280x720', "-framerate", "50", "-i" ,NAME_in, "-vf", "select=gte(n\,%s)"%(posu) , "-vframes", "1", NAME_out ]
	print(command)
	output,error=subprocess.Popen(command, universal_newlines=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
	print(str(error))



df=pd.DataFrame(None,columns=['Size','Slice','Type','SliceNo.','Frame'])
if(not os.path.exists('D:\Action\Featuresext.csv')):
	df.to_csv('D:\Action\Featuresext.csv',header=True,index=False,columns=df.columns,mode='a')
else:
	pass

if (posu==None):
	print('generating 5 random pos')
	for posi in random.sample(allowedIDS,5):
		i=0
		rem=int((posi-4)/600)+1
		if (int(posi%600)<28 and int(posi%600)>15):
			A=conceal_p1(s,posi)
		else:
			A=conceal(s,posi) 

		ret1=find_frame(posi,rem)
		ret2=find_poc(posi,rem)
		A.append(ret1)
		A.append(posi+1)
		A.append(ret2)
		print(A)
		df.loc[0]=A
		df.to_csv('D:\Action\Featuresext.csv',header=False,index=False,columns=df.columns, mode='a')
		extract_frame(name,ret2,A)

else:
	print('using the given pos:'+ ' ' + str( posu))
	posu=int(posu)-1
	rem=int((posu-4)/600)+1
	if posu in allowedIDS:
		if (int(posu%600)<28 and int(posu%600)>15):
			A=conceal_p1(s,posu)
		else:
			A=conceal(s,posu)
		ret1=find_frame(posu,rem)
		ret2=find_poc(posu,rem)
		A.append(ret1)
		A.append(posu+1)
		A.append(ret2)
		df.loc[0]=A
		df.to_csv('D:\Action\Featuresext.csv',header=False,index=False,columns=df.columns, mode='a')
		extract_frame(name,ret2,A)
		
	else:
		print('Not allowed')
